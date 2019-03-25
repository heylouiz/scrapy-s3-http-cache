import gzip
import io
import re
import time
import tempfile
import shutil
import unittest
from contextlib import contextmanager
import pytest

from botocore.response import StreamingBody
from w3lib.http import headers_dict_to_raw
from six.moves import cPickle as pickle
from scrapy.exceptions import NotConfigured
from scrapy.http import Response, HtmlResponse, Request
from scrapy.spiders import Spider
from scrapy.settings import Settings
from scrapy.utils.test import get_crawler
from scrapy.downloadermiddlewares.httpcache import HttpCacheMiddleware


class S3CacheStorageTest(unittest.TestCase):

    storage_class = 'scrapy_s3_http_cache.S3CacheStorage'
    policy_class = 'scrapy.extensions.httpcache.DummyPolicy'
    spider_name = 's3cache_spider'

    def setUp(self):
        self.crawler = get_crawler(Spider)
        self.spider = self.crawler._create_spider(self.spider_name)
        self.tmpdir = tempfile.mkdtemp()
        self.request = Request('http://www.example.com',
                               headers={'User-Agent': 'test'})
        self.response = Response('http://www.example.com',
                                 headers={'Content-Type': 'text/html'},
                                 body=b'test body',
                                 status=202)
        self.crawler.stats.open_spider(self.spider)
        self.cached_response = {
            'meta': {
                'url': self.request.url,
                'method': self.request.method,
                'status': self.response.status,
                'response_url': self.response.url,
                'timestamp': time.time(),
            },
            'response_headers': headers_dict_to_raw(self.response.headers),
            'response_body': self.response.body,
            'request_headers': headers_dict_to_raw(self.request.headers),
            'request_body': self.request.body
        }
        self.pickled_cached_response = pickle.dumps(self.cached_response)
        self.get_object_response = {
            'Body': StreamingBody(
                io.BytesIO(self.pickled_cached_response),
                len(self.pickled_cached_response)
            )
        }
        self.gzipped_pickled_cached_response = gzip.compress(self.pickled_cached_response)
        self.get_object_response_gziped = {
            'Body': StreamingBody(
                io.BytesIO(self.gzipped_pickled_cached_response),
                len(self.gzipped_pickled_cached_response)
            )
        }

    def tearDown(self):
        self.crawler.stats.close_spider(self.spider, '')
        shutil.rmtree(self.tmpdir)

    def _get_settings(self, **new_settings):
        settings = {
            'HTTPCACHE_ENABLED': True,
            'HTTPCACHE_DIR': self.tmpdir,
            'HTTPCACHE_EXPIRATION_SECS': 1,
            'HTTPCACHE_IGNORE_HTTP_CODES': [],
            'HTTPCACHE_POLICY': self.policy_class,
            'HTTPCACHE_STORAGE': self.storage_class,
            'AWS_ACCESS_KEY_ID': 'dummy',
            'AWS_SECRET_ACCESS_KEY': 'dummy',
            'S3CACHE_URI': 's3://bucket/%(name)s/%(day)s/%(name)s-%(version)s-%(time)s',
        }
        settings.update(new_settings)
        return Settings(settings)

    @contextmanager
    def _storage(self, **new_settings):
        with self._middleware(**new_settings) as mw:
            yield mw.storage

    @contextmanager
    def _policy(self, **new_settings):
        with self._middleware(**new_settings) as mw:
            yield mw.policy

    @contextmanager
    def _middleware(self, **new_settings):
        settings = self._get_settings(**new_settings)
        mw = HttpCacheMiddleware(settings, self.crawler.stats)
        mw.spider_opened(self.spider)
        try:
            yield mw
        finally:
            mw.spider_closed(self.spider)

    @contextmanager
    def _client_stubber(self, storage):
        stubber = storage._client_stubber
        stubber.activate()
        try:
            yield stubber
        finally:
            stubber.assert_no_pending_responses()
            stubber.deactivate()

    def assertEqualResponse(self, response1, response2):
        self.assertEqual(response1.url, response2.url)
        self.assertEqual(response1.status, response2.status)
        self.assertEqual(response1.headers, response2.headers)
        self.assertEqual(response1.body, response2.body)

    """ These tests are the same from FilesystemCacheStorage, just to make sure our class doesn't break anything """
    def test_storage(self):
        with self._storage() as storage:
            with self._client_stubber(storage) as stubber:
                stubber.add_client_error('get_object')
                request2 = self.request.copy()
                assert storage.retrieve_response(self.spider, request2) is None

            with self._client_stubber(storage) as stubber:
                stubber.add_response('put_object', {})
                stubber.add_response('get_object', self.get_object_response)
                storage.store_response(self.spider, self.request, self.response)
                response2 = storage.retrieve_response(self.spider, request2)
                assert isinstance(response2, HtmlResponse)  # content-type header
                self.assertEqualResponse(self.response, response2)

    def test_dont_cache(self):
        with self._middleware() as mw:
            with self._client_stubber(mw.storage) as stubber:
                stubber.add_client_error('get_object')
                self.request.meta['dont_cache'] = True
                mw.process_response(self.request, self.response, self.spider)
                self.assertEqual(mw.storage.retrieve_response(self.spider, self.request), None)

        with self._middleware() as mw:
            with self._client_stubber(mw.storage) as stubber:
                stubber.add_response('put_object', {})
                stubber.add_response('get_object', self.get_object_response)
                self.request.meta['dont_cache'] = False
                mw.process_response(self.request, self.response, self.spider)
                if mw.policy.should_cache_response(self.response, self.request):
                    self.assertIsInstance(
                        mw.storage.retrieve_response(self.spider, self.request),
                        self.response.__class__
                    )

    def test_dont_retrieve(self):
        settings = {
            'S3CACHE_DONT_RETRIEVE': True
        }
        with self._storage(**settings) as storage:
            assert storage.retrieve_response(self.spider, self.request) is None

    def test_disabled(self):
        settings = {
            'HTTPCACHE_ENABLED': False
        }
        with pytest.raises(NotConfigured):
            with self._storage(**settings) as storage:
                storage.__init__(settings)

    def test_s3cache_uri_not_configured(self):
        settings = {
            'S3CACHE_URI': None
        }
        with pytest.raises(NotConfigured, match='S3CACHE_URI must be specified'):
            with self._storage(**settings) as storage:
                storage.__init__(settings)

    def test_keypath_not_configured(self):
        settings = {
            'S3CACHE_URI': 's3://user:pass@bucket',
        }
        with pytest.raises(NotConfigured, match='Could not get key path from S3CACHE_URI'):
            with self._storage(**settings) as storage:
                storage.__init__(settings)

    def test_aws_credentials_not_configured(self):
        settings = {
            'S3CACHE_URI': 's3://:aws_secret_access_key@bucket/keypath',
            'AWS_ACCESS_KEY_ID': None,
        }
        with pytest.raises(NotConfigured, match='AWS_ACCESS_KEY_ID must be specified'):
            with self._storage(**settings) as storage:
                storage.__init__(settings)

        settings = {
            'S3CACHE_URI': 's3://aws_access_key_id@bucket/keypath',
            'AWS_SECRET_ACCESS_KEY': None,
        }
        with pytest.raises(NotConfigured, match='AWS_SECRET_ACCESS_KEY must be specified'):
            with self._storage(**settings) as storage:
                storage.__init__(settings)

    def test_bucket_name_not_configured(self):
        settings = {
            'S3CACHE_URI': 's3://user:pass@/heypath',
        }
        with pytest.raises(NotConfigured, match='Could not get bucket name from S3CACHE_URI'):
            with self._storage(**settings) as storage:
                storage.__init__(settings)

    def test_uri_parse(self):
        settings = {
            'S3CACHE_URI': 's3://aws_access_key:aws_secret_key@bucketname/%(name)s/%(name)s-%(time)s.zip'
        }
        with self._storage(**settings) as storage:
            self.assertEqual(storage.bucket_name, 'bucketname')
            self.assertEqual(storage.access_key, 'aws_access_key')
            self.assertEqual(storage.secret_key, 'aws_secret_key')
            self.assertEqual(storage.keypath_fmt, '%(name)s/%(name)s-%(time)s.zip')

    def test_keypath(self):
        settings = {
            'S3CACHE_URI': 's3://aws_access_key:aws_secret_key@bucketname/%(name)s/%(name)s-%(time)s.zip'
        }
        with self._storage(**settings) as storage:
            keypath_regex = '{spider_name}/{spider_name}-'.format(spider_name=self.spider_name)
            date_regex = r'\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}'
            keypath_regex = keypath_regex + date_regex
            assert re.match(keypath_regex, storage.keypath) is not None

        keypath = '1234567'
        settings = {
            'S3CACHE_URI': 's3://bucketname/{keypath}'.format(keypath=keypath)
        }
        with self._storage(**settings) as storage:
            assert keypath == storage.keypath

    def test_invalid_spider(self):
        with pytest.raises(NotConfigured, match='Could not get spider! Aborting...'):
            with self._storage() as storage:
                storage.open_spider(None)
                storage.spider

    def test_failed_to_get_object_from_s3(self):
        with self._storage() as storage:
            with self._client_stubber(storage) as stubber:
                stubber.add_client_error('get_object')
                storage.get_object_from_key('bucket', 'key')

    def test_failed_to_put_object_to_s3(self):
        with self._storage() as storage:
            with self._client_stubber(storage) as stubber:
                stubber.add_client_error('put_object')
                storage.put_object_to_key(b'file', 'bucket', 'key')


if __name__ == '__main__':
    unittest.main()
