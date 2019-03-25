# scrapy-s3-http-cache

S3 storage backend for Scrapy's HTTP cache middleware

## How to enable

This extension relies on Scrapy cache mechanism, which should be enabled and configured.
For more information see [Scrapy documentation on this topic](https://docs.scrapy.org/en/latest/topics/downloader-middleware.html#module-scrapy.downloadermiddlewares.httpcache).

These two settings should be enough:

```
HTTPCACHE_ENABLED = True
HTTPCACHE_STORAGE = 'scrapy_s3_http_cache.S3CacheStorage'
```

## Settings

The settings below can be defined as any other Scrapy settings, as described on [Scrapy docs](https://docs.scrapy.org/en/latest/topics/settings.html).

`S3CACHE_URI`: the URI where the cache should be stored.

    Eg: 's3://aws_key:aws_secret@bucket/%(name)s-%(time)s'

    %(name)s will be replaced by the Spider name attribute and %(time)s with the timestamp in iso format of the spider finish time.

`S3CACHE_DONT_RETRIEVE`: Do not retrieve responses from the cache, only for storage. Default: False.

### Other settings:

`HTTPCACHE_GZIP`: Compress the cached responses using gzip. Default: False.
