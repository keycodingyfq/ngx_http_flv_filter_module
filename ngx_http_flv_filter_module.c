#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static u_char  ngx_flv_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";

#define FLV_UI32(x) (int)(((x[0]) << 24) + ((x[1]) << 16) + ((x[2]) << 8) + (x[3]))
#define FLV_UI24(x) (int)(((x[0]) << 16) + ((x[1]) << 8) + (x[2]))
#define FLV_UI16(x) (int)(((x[0]) << 8) + (x[1]))
#define FLV_UI8(x) (int)((x))

#define FLV_H263VIDEOPACKET     2
#define FLV_SCREENVIDEOPACKET   3
#define FLV_VP6VIDEOPACKET      4
#define FLV_VP6ALPHAVIDEOPACKET 5
#define FLV_SCREENV2VIDEOPACKET 6
#define FLV_AVCVIDEOPACKET      7

#define FLV_AUDIODATA   8
#define FLV_VIDEODATA   9
#define FLV_SCRIPTDATAOBJECT    18

typedef struct {
	unsigned char signature[3];
	unsigned char version;
	unsigned char flags;
	unsigned char headersize[4];
} flv_file_header_t;


typedef struct {
	 unsigned char type;
	 unsigned char datasize[3];
	 unsigned char timestamp[3];
	 unsigned char timestamp_ex;
	 unsigned char streamid[3];
} flv_tag_t;


typedef struct {
	u_char flags;
} flv_video_header_t;

typedef struct {
	ngx_flag_t enable;
} ngx_http_flv_conf_t;

typedef struct {
	 ngx_int_t status;
	 off_t     arg_start, arg_end;
	 off_t     offset, startset;
	 off_t     next_tag, cur_tag;
	 ngx_buf_t *buff;
} ngx_http_flv_ctx_t;


ngx_module_t  ngx_http_flv_filter_module;
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static void flv_memcpy(ngx_buf_t *dst, ngx_buf_t *src, u_char *cur_pos, size_t len)
{
	 size_t nlen = (size_t)(src->last - cur_pos);
	 len = (nlen < len) ? nlen : len;

	 ngx_memcpy(dst->last, cur_pos, len);

	 dst->last += len;

	 return;
}

static void flv_read_header(ngx_http_flv_ctx_t *ctx, ngx_buf_t *src)
{
	 size_t len = sizeof(flv_file_header_t) + 4 - (ctx->buff->last - ctx->buff->pos);
	 u_char *cur_pos = src->pos + (ctx->buff->last - ctx->buff->pos);

	 flv_memcpy(ctx->buff, src, cur_pos, len);
	 if ((unsigned long)(ctx->buff->last - ctx->buff->pos) >= len) {
		  flv_file_header_t *header = (flv_file_header_t *)ctx->buff->pos;
		  fprintf(stderr, "liuheng::ngx_http_flv_body_filter header: %s %d\n", header->signature, FLV_UI32(header->headersize));

		  ctx->next_tag = sizeof(flv_file_header_t) + 4;
		  ctx->cur_tag = ctx->next_tag;

		  ctx->buff->pos = ctx->buff->start;
		  ctx->buff->last = ctx->buff->start;
		  ctx->status = 1;
	 }

	 return;
}

static flv_tag_t *flv_read_tag(ngx_http_flv_ctx_t *ctx, ngx_buf_t *src)
{
	 if (ctx->offset < ctx->next_tag) {
		  return NULL;
	 }

	 u_char *cur_pos = src->pos + (ctx->next_tag - ctx->startset) - (ctx->buff->last - ctx->buff->pos);

	 flv_memcpy(ctx->buff, src, cur_pos, sizeof(flv_tag_t));
	 if ((unsigned long)(ctx->buff->last - ctx->buff->pos) >= sizeof(flv_tag_t)) {
		  flv_tag_t *tag = (flv_tag_t *)ctx->buff->pos;

		  ctx->cur_tag = ctx->next_tag;
		  ctx->next_tag += sizeof(flv_tag_t) + FLV_UI24(tag->datasize) + 4;

		  ctx->buff->pos = ctx->buff->start;
		  ctx->buff->last = ctx->buff->start;

		  return tag;
	 }

	 return NULL;
}

static ngx_int_t
ngx_http_flv_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	 ngx_chain_t *cl;
	 ngx_buf_t *buf;
	 ngx_http_flv_ctx_t *ctx;
	 size_t size = 0;

	 ctx = ngx_http_get_module_ctx(r, ngx_http_flv_filter_module);
	 if (ctx == NULL) {
		  return ngx_http_next_body_filter(r, in);
	 }
	 if (ctx->arg_start == 0 && ctx->arg_end == 0) {
		  return ngx_http_next_body_filter(r, in);
	 }

	 for (cl = in; cl; cl = cl->next) {
		  buf = cl->buf;

		  ctx->startset = ctx->offset;
		  ctx->offset = ctx->offset + ngx_buf_size(buf);

		  fprintf(stderr, "liuheng::flv: %lld-%lld %lld %lld %lld %lld %ld\n",
				  ctx->arg_start, ctx->arg_end, ngx_buf_size(buf), ctx->next_tag, ctx->startset, ctx->offset, ctx->status);

		  if (ctx->status == 0) {
			   ctx->cur_tag = 0;
			   ctx->next_tag = 0;

			   flv_read_header(ctx, buf);
		  }

		  //  start...
		  if (ctx->status == 1) {
			   while (NULL != flv_read_tag(ctx, buf)) {
					flv_tag_t *tag = (flv_tag_t *)ctx->buff->pos;

					// fprintf(stderr, "liuheng::ngx_http_flv_body_filter tag: %d %d\n", FLV_UI8(tag->type), FLV_UI24(tag->datasize));

					if (ctx->cur_tag >= ctx->arg_start) {
						 buf->pos += (ctx->cur_tag - ctx->startset);
						 ctx->startset = ctx->cur_tag;

						 // header
						 ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
						 if (b == NULL) {
							  return NGX_HTTP_INTERNAL_SERVER_ERROR;
						 }

						 b->pos = ngx_flv_header;
						 b->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;
						 b->memory = 1;

						 ngx_chain_t out;
						 out.buf = b;
						 out.next = cl;
						 in = &out;

						 
						 ctx->status ++;
						 size += ngx_buf_size(cl->buf) + ngx_buf_size(b);

						 fprintf(stderr, "liuheng::ngx_http_flv_body_filter started tag: %d %d %lld %lld %lld\n",
								 FLV_UI8(tag->type), FLV_UI24(tag->datasize), ctx->cur_tag, ctx->arg_start, ctx->startset);

						 break;
					}
			   }

			   if (0 == size) {
					buf->pos = buf->last;
			   }
		  }

		  if (ctx->status == 2) {
			   size += ngx_buf_size(cl->buf);
			   
			   // end...
			   if (ctx->arg_end > 0) {
					while(NULL != flv_read_tag(ctx, buf)) {
						 flv_tag_t *tag = (flv_tag_t *)ctx->buff->pos;
						 
						 fprintf(stderr, "liuheng::ngx_http_flv_body_filter end tag: %d %d %lld %lld\n",
								 FLV_UI8(tag->type), FLV_UI24(tag->datasize), ctx->cur_tag, ctx->arg_end);

							 
						 if (ctx->cur_tag >= ctx->arg_end) {
							  buf->last = buf->pos + (ctx->next_tag - ctx->startset) - 1;
							  
							  buf->last_buf =  1;
							  buf->last_in_chain = 1;
							  
							  cl->next = NULL;
							  
							  fprintf(stderr, "liuheng:: ended>>>%lld %lld\n\n", ctx->next_tag, ctx->arg_end);
							  
							  break;
						 }
					}
			   }
		  }

	 } // for

	 if (0 == size && ctx->status < 2) {
		  fprintf(stderr, "okok\n");
		  return NGX_AGAIN;
	 }

	 return ngx_http_next_body_filter(r, in);
}


static ngx_int_t
ngx_http_flv_header_filter(ngx_http_request_t *r)
{
	 ngx_str_t            value;
	 off_t                start = 0;
	 off_t                end = 0;
	 ngx_http_flv_ctx_t   *ctx;
	 ngx_http_flv_conf_t  *slcf;

	 slcf = ngx_http_get_module_loc_conf(r, ngx_http_flv_filter_module);

	 if (!slcf->enable)
	 {
		  return ngx_http_next_header_filter(r);
	 }

	 if (r->headers_out.status != NGX_HTTP_OK || r != r->main || !r->args.len) {
		  return ngx_http_next_header_filter(r);
	 }


	 if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK)
	 {
		  start = ngx_atoof(value.data, value.len);
		  if (start == NGX_ERROR || start >= r->headers_out.content_length_n) {
			   start = 0;
		  }

		  if (start < 0) {
			   start = 0;
		  }
	 }

	 if (ngx_http_arg(r, (u_char *) "end", 3, &value) == NGX_OK) {
		  end = ngx_atoof(value.data, value.len);
		  if (end > 0) {
			   if (end <= start) {
					return NGX_HTTP_RANGE_NOT_SATISFIABLE;
			   }
		  }
	 }

	 if (start) {
		  ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_flv_ctx_t));
		  if (ctx == NULL) {
			   return NGX_ERROR;
		  }
		  ngx_http_set_ctx(r, ctx, ngx_http_flv_filter_module);

		  ctx->buff = ngx_create_temp_buf(r->pool, 32);
		  if (ctx->buff  == NULL) {
			   return NGX_ERROR;
		  }

		  ctx->arg_start = start;
		  ctx->arg_end = end;
		  ctx->offset = 0;
		  ctx->startset = 0;
		  ctx->status = 0;

		  ngx_http_clear_content_length(r);
		  ngx_http_clear_accept_ranges(r);
		  ngx_http_weak_etag(r);

		  r->filter_need_in_memory = 1;
	 }

	 return ngx_http_next_header_filter(r);
}


static void *
ngx_http_flv_create_conf(ngx_conf_t *cf)
{
	ngx_http_flv_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flv_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     conf->bufs.num = 0;
	 *     conf->types = { NULL };
	 *     conf->types_keys = NULL;
	 */

	conf->enable = NGX_CONF_UNSET;

	return conf;
}


static char *
ngx_http_flv_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_flv_conf_t *prev = parent;
	ngx_http_flv_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);

	return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_flv_filter_init(ngx_conf_t *cf)
{
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_flv_header_filter;

	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_flv_body_filter;

	return NGX_OK;
}


///////////////////////////
static ngx_command_t  ngx_http_flv_filter_commands[] = {
	{ ngx_string("flv_filter"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
						|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_flv_conf_t, enable),
	  NULL },

	  ngx_null_command
};

static ngx_http_module_t  ngx_http_flv_filter_module_ctx = {
	NULL,                          /* preconfiguration */
	ngx_http_flv_filter_init,      /* postconfiguration */

	NULL,                          /* create main configuration */
	NULL,                          /* init main configuration */

	NULL,                          /* create server configuration */
	NULL,                          /* merge server configuration */

	ngx_http_flv_create_conf,       /* create location configuration */
	ngx_http_flv_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_flv_filter_module = {
	NGX_MODULE_V1,
	&ngx_http_flv_filter_module_ctx,      /* module context */
	ngx_http_flv_filter_commands,         /* module directives */
	NGX_HTTP_MODULE,               /* module type */
	NULL,                          /* init master */
	NULL,                          /* init module */
	NULL,                          /* init process */
	NULL,                          /* init thread */
	NULL,                          /* exit thread */
	NULL,                          /* exit process */
	NULL,                          /* exit master */
	NGX_MODULE_V1_PADDING
};
