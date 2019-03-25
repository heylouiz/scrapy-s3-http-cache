import boto3
import gzip
import json
import logging
import os
import subprocess
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from contextlib import suppress
from time import time
from datetime import datetime
from six.moves import cPickle as pickle
from six.moves.urllib.parse import urlparse
from scrapy.exceptions import NotConfigured
from scrapy.http import Headers
from scrapy.responsetypes import responsetypes
from scrapy.utils.request import request_fingerprint
from w3lib.http import headers_raw_to_dict, headers_dict_to_raw

logger = logging.getLogger(__name__)


def get_job_version():
    shub_job_version = json.loads(os.environ.get('SHUB_JOB_DATA', '{}')).get('version')
    if shub_job_version:
        return shub_job_version
    with suppress(subprocess.CalledProcessError):
        git_hash = subprocess.check_output(['git', 'describe', '--always']).strip()
        return git_hash.decode('utf-8')
    return 'no-version'


def configure_log_level(level):
    import s3transfer  # NOQA used to configure log level
    boto_modules = ['boto', 's3transfer', 'boto3', 'botocore']
    for name in logging.Logger.manager.loggerDict.keys():
        for module in boto_modules:
            if module in name:
                logging.getLogger(name).setLevel(level)


class S3CacheStorage(object):
    """ S3 storage backend for Scrapy's HTTP cache middleware

        Settings:

        The settings below can be defined as any other Scrapy settings, as described on Scrapy docs.

        S3CACHE_URI: the URI where the cache should be stored.
           Eg: 's3://aws_key:aws_secret@bucket/%(name)s-%(time)s'
        S3CACHE_DONT_RETRIEVE: Do not retrieve responses from the cache, only for storage. Default: False.

        This extension relies on Scrapy cache mechanism, which should be enabled and configured.
        See: https://docs.scrapy.org/en/latest/topics/downloader-middleware.html#module-scrapy.downloadermiddlewares.httpcache  # NOQA
        These two settings are usually enough:
        HTTPCACHE_ENABLED = True
        HTTPCACHE_STORAGE = 'scrapy-s3-http-cache.s3cache.S3CacheStorage'

        Other settings:
        HTTPCACHE_GZIP: Compress the cached responses using gzip. Default: False.

    """

    def __init__(self, settings):
        urifmt = settings.get('S3CACHE_URI', '')
        if not urifmt:
            raise NotConfigured('S3CACHE_URI must be specified')

        # Parse URI
        u = urlparse(urifmt)
        self.keypath_fmt = u.path[1:]
        if not self.keypath_fmt:
            raise NotConfigured('Could not get key path from S3CACHE_URI')

        self.access_key = u.username or settings['AWS_ACCESS_KEY_ID']
        if self.access_key is None:
            raise NotConfigured('AWS_ACCESS_KEY_ID must be specified')

        self.secret_key = u.password or settings['AWS_SECRET_ACCESS_KEY']
        if self.secret_key is None:
            raise NotConfigured('AWS_SECRET_ACCESS_KEY must be specified')

        self.bucket_name = u.hostname
        if self.bucket_name is None:
            raise NotConfigured('Could not get bucket name from S3CACHE_URI')

        self.use_gzip = settings.getbool('HTTPCACHE_GZIP')
        self.dont_retrieve = settings.getbool('S3CACHE_DONT_RETRIEVE')

        self._client = None
        self._spider = None
        self._keypath = None
        self.cached_requests = []

        # Configure log level for all modules related do s3 access
        configure_log_level(logging.INFO)

    @property
    def _client_stubber(self):
        """ Returns a stubber for the s3 client object to help on unit tests
            See: https://botocore.amazonaws.com/v1/documentation/api/latest/reference/stubber.html
        """
        return Stubber(self.client)

    @property
    def client(self):
        """ Connect to S3 and return the connection """
        if self._client is None:
            self._client = boto3.client('s3', aws_access_key_id=self.access_key, aws_secret_access_key=self.secret_key)
        return self._client

    @property
    def keypath(self):
        """ Get the keypath as specified in S3CACHE_URI """
        def get_uri_params(obj):
            """Convert an object to a dict"""
            params = {}
            for k in dir(obj):
                params[k] = getattr(obj, k)
            params['day'] = datetime.utcnow().strftime('%Y-%m-%d')
            params['time'] = datetime.utcnow().replace(microsecond=0).isoformat().replace(':', '-')
            params['version'] = get_job_version()
            return params
        if not self._keypath:
            self._keypath = self.keypath_fmt % get_uri_params(self.spider)
        return self._keypath

    @property
    def spider(self):
        if not self._spider:
            raise NotConfigured('Could not get spider! Aborting...')
        return self._spider

    def put_object_to_key(self, obj, bucket, key):
        try:
            obj = gzip.compress(obj) if self.use_gzip else obj
            self.client.put_object(Body=obj, Bucket=bucket, Key=key)
        except ClientError as e:
            logger.warning('Failed to store cache on key {key}: {e}'.format(key=key, e=e))

    def get_object_from_key(self, bucket, key):
        try:
            response = self.client.get_object(Bucket=bucket, Key=key)
            obj = response['Body'].read()
            return gzip.decompress(obj) if self.use_gzip else obj
        except ClientError as e:
            logger.warning('Failed to retrieve cache on key {key}: {e}'.format(key=key, e=e))

    def open_spider(self, spider):
        logger.debug('Using s3 cache storage in %(bucket_name)s' % {'bucket_name': self.bucket_name},
                     extra={'spider': spider})
        # Update spider reference
        self._spider = spider

    def close_spider(self, spider):
        logger.info(
            'Cache on s3 bucket {bucket} on key path {keypath}'.format(bucket=self.bucket_name, keypath=self.keypath),
            extra={'spider': spider}
        )

    def retrieve_response(self, spider, request):
        """Return response if present in cache, or None otherwise."""
        if self.dont_retrieve:
            return
        keyname = self._get_request_path(request)
        keydata = self.get_object_from_key(self.bucket_name, keyname)
        if not keydata:
            return  # not cached
        keydata = pickle.loads(keydata)
        metadata = keydata['meta']
        body = keydata['response_body']
        rawheaders = keydata['response_headers']
        url = metadata.get('response_url')
        status = metadata['status']
        headers = Headers(headers_raw_to_dict(rawheaders))
        respcls = responsetypes.from_args(headers=headers, url=url)
        response = respcls(url=url, headers=headers, status=status, body=body)
        return response

    def store_response(self, spider, request, response):
        # TODO: Use a buffer instead of sending the cache files one by one
        """Store the given response in the cache."""
        keyname = self._get_request_path(request)
        metadata = {
            'url': request.url,
            'method': request.method,
            'status': response.status,
            'response_url': response.url,
            'timestamp': time(),
        }
        keydata = {
            'meta': metadata,
            'response_headers': headers_dict_to_raw(response.headers),
            'response_body': response.body,
            'request_headers': headers_dict_to_raw(request.headers),
            'request_body': request.body
        }
        self.put_object_to_key(pickle.dumps(keydata), self.bucket_name, keyname)

    def _get_request_path(self, request):
        key = request_fingerprint(request)
        return '{keypath}/{key}'.format(keypath=self.keypath, key=key)
