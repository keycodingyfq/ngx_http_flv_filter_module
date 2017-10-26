# ngx_http_flv_filter_module
让nginx支持flv流式播放(start,end)，而且同时可以开启proxy cache.

nginx 本身的flv模块实现得很简单：

1. 只支持start不支持end，这样的话前端就不能分段播放。
2. start的行为跟http标准的range请求一样，只是做了文件的seek，没有考虑flv文件的tag对齐，这样就需要播放器做容错处理，不能直接播放。我测试的过程中， 除了迅雷看看能播放， FLC和一些在线flv播放器都播放不了。
3. 不能和proxy-cache一起使用，也就是说不能用nginx做代理， 只有文件在本机存储的情况下才能用。

简单来说，这种简单的实现基本没法用在实际产品中。我们需要支持start/end，miss 拖拽，需要和proxy-cache一起工作 。

[中文文档](https://www.sixianed.com/2017/10/11/cj95g3yaj000zakye8yj0w5s4.html)
