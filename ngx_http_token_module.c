
/*
* Copyright (C) Igor Sysoev
*/


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

typedef struct {
	ngx_http_upstream_conf_t	upstream;
	ngx_flag_t					enable;
	ngx_str_t					key;
	ngx_uint_t					token_len;
} ngx_http_token_loc_conf_t;

typedef struct {
	size_t                     rest;
	ngx_http_request_t         *request;
	ngx_str_t                  key;
	ngx_uint_t				   index;	
} ngx_http_token_ctx_t;

static ngx_int_t ngx_http_token_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_token_process_header(ngx_http_request_t *r);

static void ngx_http_token_abort_request(ngx_http_request_t *r);
static void ngx_http_token_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

static void *ngx_http_token_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_token_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_token_commands[] = {

	{ ngx_string("token"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	ngx_conf_set_flag_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_token_loc_conf_t, enable),
	NULL },

	{ ngx_string("token_key"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_str_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_token_loc_conf_t, key),
	NULL },

	{ ngx_string("token_len"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_conf_set_num_slot,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_token_loc_conf_t, token_len),
	NULL },

	{ ngx_string("token_server"),
	NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	ngx_http_token_server,
	NGX_HTTP_LOC_CONF_OFFSET,
	0,
	NULL },

	ngx_null_command
};


static ngx_http_module_t  ngx_http_token_module_ctx = {
	NULL,                                  /* preconfiguration */
	NULL,                                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_token_create_loc_conf,    /* create location configration */
	ngx_http_token_merge_loc_conf      /* merge location configration */
};


ngx_module_t  ngx_http_token_module = {
	NGX_MODULE_V1,
	&ngx_http_token_module_ctx,        /* module context */
	ngx_http_token_commands,           /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


#define NGX_HTTP_MEMCACHED_END   (sizeof(ngx_http_memcached_end) - 1)
static u_char  ngx_http_memcached_end[] = CRLF "END" CRLF;


static ngx_int_t
ngx_http_token_handler(ngx_http_request_t *r)
{
	ngx_http_upstream_t        *u;
	ngx_http_token_ctx_t       *ctx;
	ngx_http_token_loc_conf_t  *tlcf;

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	tlcf = ngx_http_get_module_loc_conf(r, ngx_http_token_module);

	ngx_str_t args = r->args;
	ngx_str_t key = tlcf->key;

	ngx_uint_t i = 0;

	if ( args.len > (tlcf->token_len + key.len)){
		for (; i < args.len; i++){
			if (args.data[i] == '=' 
				&& i >= key.len
				&& ngx_strncmp(args.data + i - key.len, key.data, key.len) == 0
				&& (args.data[i + tlcf->token_len + 1] == '&'
				|| (i + tlcf->token_len + 1) == args.len)){
					break;
			}
		}
	}

	if ( i < key.len || (args.len - i) < tlcf->token_len){
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "token:%V pos:%d args:%V.", &tlcf->key, i, &args);
		return NGX_HTTP_FORBIDDEN;
	}

	u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
	if (u == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	u->schema = tlcf->upstream.schema;

	u->peer.log = r->connection->log;
	u->peer.log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
	u->peer.lock = &r->connection->lock;
#endif

	u->output.tag = (ngx_buf_tag_t) &ngx_http_token_module;

	u->conf = &tlcf->upstream;

	u->create_request = ngx_http_token_create_request;
	u->process_header = ngx_http_token_process_header;
	u->abort_request = ngx_http_token_abort_request;
	u->finalize_request = ngx_http_token_finalize_request;

	ctx = ngx_palloc(r->pool, sizeof(ngx_http_token_ctx_t));
	if (ctx == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	r->upstream = u;

	ctx->rest = NGX_HTTP_MEMCACHED_END;
	ctx->request = r;
	ctx->index	= i;

	ngx_http_set_ctx(r, ctx, ngx_http_token_module);

	ngx_http_upstream_init(r);	
	
	return NGX_DONE;
}


static ngx_int_t
ngx_http_token_create_request(ngx_http_request_t *r)
{
	
	size_t                          len;
	uintptr_t                       escape;
	ngx_buf_t						*b;
	ngx_chain_t						*cl;
	ngx_http_token_ctx_t			*ctx;
	ngx_http_token_loc_conf_t		*tlcf;

	ngx_str_t args = r->args;

	tlcf = ngx_http_get_module_loc_conf(r, ngx_http_token_module);
	ctx = ngx_http_get_module_ctx(r, ngx_http_token_module);

	escape = 2 * ngx_escape_uri(NULL, args.data + (ctx->index + 1), tlcf->token_len, NGX_ESCAPE_MEMCACHED);

	len = sizeof("get ") - 1 + tlcf->token_len + escape + sizeof(CRLF) - 1;

	b = ngx_create_temp_buf(r->pool, len);
	if (b == NULL) {
		return NGX_ERROR;
	}

	cl = ngx_alloc_chain_link(r->pool);
	if (cl == NULL) {
		return NGX_ERROR;
	}

	cl->buf = b;
	cl->next = NULL;

	r->upstream->request_bufs = cl;

	*b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';

	ctx->key.data = b->last;

	if (escape == 0) {
		b->last = ngx_copy(b->last, args.data + (ctx->index + 1), tlcf->token_len);
	} else {
		b->last = (u_char *) ngx_escape_uri(b->last, args.data + (ctx->index + 1), tlcf->token_len, NGX_ESCAPE_MEMCACHED);
	}

	ctx->key.len = b->last - ctx->key.data;

	*b->last++ = CR; *b->last++ = LF;

	return NGX_OK;
}


static ngx_int_t
ngx_http_token_process_header(ngx_http_request_t *r)
{

	u_char						*p;
	ngx_http_upstream_t			*u;
	ngx_http_token_ctx_t		*ctx;
	ngx_http_token_loc_conf_t	*tlcf;

	tlcf = ngx_http_get_module_loc_conf(r, ngx_http_token_module);
	ctx = ngx_http_get_module_ctx(r, ngx_http_token_module);

	u = r->upstream;

	for (p = u->buffer.pos; p < u->buffer.last; p++) {
		if (*p == LF) {
			goto ok;
		}
	}

	goto fail;

ok:
	*p = '\0';

	p = u->buffer.pos;

	if (ngx_strncmp(p, "VALUE ", sizeof("VALUE ") - 1) == 0) {

		u->headers_in.status_n = 404;
		u->state->status = 404;

		return NGX_OK;
	}

fail:
	ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "token: \"%V\" fail", &ctx->key);

	u->headers_in.status_n = 403;
	u->state->status = 403;

	return NGX_ERROR;
}

static void
ngx_http_token_abort_request(ngx_http_request_t *r)
{
	return;
}


static void
ngx_http_token_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
	return;
}

static void *
ngx_http_token_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_token_loc_conf_t  *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_token_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
	conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

	conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

	/* the hardcoded values */
	conf->upstream.cyclic_temp_file = 0;
	conf->upstream.buffering = 0;
	conf->upstream.ignore_client_abort = 0;
	conf->upstream.send_lowat = 0;
	conf->upstream.bufs.num = 0;
	conf->upstream.busy_buffers_size = 0;
	conf->upstream.max_temp_file_size = 0;
	conf->upstream.temp_file_write_size = 0;
	conf->upstream.intercept_errors = 1;
	conf->upstream.intercept_404 = 1;
	conf->upstream.pass_request_headers = 0;
	conf->upstream.pass_request_body = 0;

	conf->token_len = NGX_CONF_UNSET_UINT;
	conf->enable = NGX_CONF_UNSET;

	return conf;
}


static char *
ngx_http_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_token_loc_conf_t *prev = parent;
	ngx_http_token_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_str_value(conf->key, prev->key, "key");
	ngx_conf_merge_size_value(conf->token_len, prev->token_len, 4);

	ngx_conf_merge_msec_value(conf->upstream.connect_timeout, prev->upstream.connect_timeout, 60000);
	ngx_conf_merge_msec_value(conf->upstream.send_timeout, prev->upstream.send_timeout, 60000);
	ngx_conf_merge_msec_value(conf->upstream.read_timeout, prev->upstream.read_timeout, 60000);
	ngx_conf_merge_size_value(conf->upstream.buffer_size, prev->upstream.buffer_size, (size_t) ngx_pagesize);

	ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
		prev->upstream.next_upstream,
		(NGX_CONF_BITMASK_SET
		|NGX_HTTP_UPSTREAM_FT_ERROR
		|NGX_HTTP_UPSTREAM_FT_TIMEOUT));

	if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
		conf->upstream.next_upstream = NGX_CONF_BITMASK_SET|NGX_HTTP_UPSTREAM_FT_OFF;
	}

	if (conf->upstream.upstream == NULL) {
		conf->upstream.upstream = prev->upstream.upstream;
		conf->upstream.schema = prev->upstream.schema;
	}
	
	return NGX_CONF_OK;
}


static char *
ngx_http_token_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_token_loc_conf_t *lcf = conf;

	ngx_str_t                 *value;
	ngx_url_t                  u;
	ngx_http_core_loc_conf_t  *clcf;

	if (lcf->upstream.schema.len) {
		return "is duplicate";
	}

	value = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = value[1];
	u.no_resolve = 1;

	lcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
	if (lcf->upstream.upstream == NULL) {
		return NGX_CONF_ERROR;
	}

	lcf->upstream.schema.len = sizeof("memcached://") - 1;
	lcf->upstream.schema.data = (u_char *) "memcached://";

	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	clcf->handler = ngx_http_token_handler;

	if (clcf->name.data[clcf->name.len - 1] == '/') {
		clcf->auto_redirect = 1;
	}

	return NGX_CONF_OK;
}
