#TRUSTED 8fa4365fb0d03145dffd242f346857973602fdbe6d2f4a13a1b6368a8ad9f8a6f2b2f99ac8530f9f1084dc03628c6f5ebd96cea92616d52e222eea8cf9558305027194657399e06a2789fc14cae0e3ab247e271e8537ff6a61911a60e8c48d41a5f4dee92b8a5f49da4f0802369840a1150f5de62839a44b6772a545d3ff9fc39b515b0beb58b76a855a47e5c8f73591aa31c4638980ebe0ae757b7129fd313ea01b012a2c4913a58945b142f9de936d8684d4c4b61e4accb5dc38311b2516ef7b08bf69aa5c3ce8304d93a6ef41182f2212b7bdf2a26cfa0288c6f8543b17b8848b32c090dd0e971c29dc269ce58878619bb2f011494443dc8e937fd3f5afbbd028ccd6e42b6d8cd5e822d86e224a3703a9279b4d6bd1fa9baaf62f4f80c46fe844f9899d9cfec88170576d9423c5b40722e6d3f7bc0581126a2a98fb116519a86d51f32bb19a50cd375b2e6acf47a839461066962904bae6cf3695a1b99eeafe73ea3e4fe96b54c0d49279b975d3117a98dd71cc320e64932a6c6db050e44782104813f8bcc536bd80577657731579392107714fd0a144b2f12307f26cc8f28c62d0b2f0adf699ab522746290c51d28df2bd83f13ff02ee81165fba2fd427f4b8a015317f22e64914a1b4273887776b2503548b7a166b1c9aec2026f000d8a6257c63ed33aaf9d56bb43e5c40a8c7c563fbd0b3f738331942bdfa19413789d
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
#
# @NOGPL@
#
# http_request.inc
# Revision: 1.28

# You need to include global_settings.inc and misc_func.inc
# NTLM
include("http_crypto_func.inc");

global_var __http_gzip_enabled;

# An HTTP request is store internally as a hash.
# Each key is a header.
# Two keys are reserved for special use:
# $request => the request line, e.g. GET / HTTP/1.0
# $data    => the payload (mainly for a POST)

wdayname = make_list('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun');
monthname = make_list('', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
	  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');


function http_set_gzip_enabled()
{
 local_var prev;

 prev = __http_gzip_enabled;
 __http_gzip_enabled = _FCT_ANON_ARGS[0];
 return prev;
}

function http_get_gzip_enabled()
{
 return __http_gzip_enabled;
}


#
# Use this function to add a Date HTTP header
#
function mkdate()
{
 local_var	t;

 t = localtime(utc: 1);
 return
  strcat(wdayname[t['wday']], ', ', 
  	t['mday'] / 10, t['mday'] % 10, ' ', 
	monthname[t['mon']], ' ', t['year'], ' ', 
	t['hour'] / 10, t['hour'] % 10, ':', 
	t['min'] / 10, t['min'] % 10, ':', 
	t['sec'] / 10, t['sec'] % 10, ' GMT' );
}

function http_mk_proxy_request(scheme, method, item, host, port, username, password, data, add_headers, version, content_type)
{
  local_var	ver, v, req, h, auth, k, t, url;

  if (method == 'CONNECT')
  {
    if (isnull(port) || isnull(host))
    {
      err_print('http_mk_proxy_request: host or port should not be NULL for CONNECT request\n');
      return NULL;
    }
  }
  else
  if (isnull(method) || isnull(host) || isnull(item) || isnull(scheme))
  {
    err_print('http_mk_proxy_request: scheme, host, method or item argument should not be NULL\n');
    return NULL;
  }

  if (isnull(CookieJar_value)) init_cookiejar();	
  # TBD: handle proxy authentication?

  req = make_array();
  if (isnull(version)) version = 11;
  else
    version = int(version);
  if (version < 10 || version > 11)
  {
    err_print('http_mk_proxy_request: invalid version: ', version, '\n');
    version = 11;
  }
  h = make_array();
  h['$method'] = method; h['$scheme'] = scheme; 
  h['$port'] = port; h['$version'] = version; h['$uri'] = item;
  url = '';
  if (method == 'CONNECT')
  {
    h['$uri'] = strcat(host, ':', port);
  }
  else
  {
   url = strcat(scheme, '://');
   if (strlen(username) > 0)
   {
    url = strcat(url, username);
    if (strlen(password) > 0)
      url = strcat(url, ':', password);
    url = strcat(url, '@');
   }
  }
  url = strcat(url, host);
  if (port > 0)
    url = strcat(url, ':', port);
  if (method != 'CONNECT')
  {
   if (item[0] != '/')
   {
    debug_print('http_mk_proxy_request: item does not start with slash: ', item);
    url = strcat(url, '/');
   }
   url = strcat(url, item);
  }
  if (version == 10) req = strcat(method, ' ', url, ' HTTP/1.0');
  else req = strcat(method, ' ', url, ' HTTP/1.1');
  h['$request'] = req;
  if (method != 'CONNECT')
  {
   if (version >= 11) h['Host'] = host;
   v = get_kb_item("global_settings/http_user_agent");
   if (! v) v = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)';
   h['User-Agent'] = v;

   h['Proxy-Connection'] = 'Close';
   h['Connection'] = 'Close';
   h['Pragma'] = 'no-cache';
   h['Accept'] = 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*';
   h['Accept-Language'] = 'en';
   h['Accept-Charset'] = 'iso-8859-1,utf-8;q=0.9,*;q=0.1';
   h['Cookie'] = mk_cookie_header(item: item);
   if (! isnull(data))
   {
    h['$data'] = data;
    h['Content-Length'] = strlen(data);
   }

   if (! isnull(content_type)) h['Content-Type'] = content_type;
  }

  if (typeof(add_headers) == "array")
    foreach k (keys(add_headers))
      h[k] = add_headers[k];

  return h;

}

function http_mk_req(port, host, method, item, version, data, add_headers, content_type)
{
  local_var	ver, v, req, h, hn, auth, k, t;

  if (isnull(port) || isnull(method))
  {
    err_print('http_mk_req: port or method argument should not be NULL');
    return NULL;
  }
  if (method != "CONNECT" && strlen(item) == 0)
  {
    err_print('http_mk_req: item argument should not be empty.');
    return NULL;
  }

  if (isnull(CookieJar_value)) init_cookiejar();	
  # temporary compatibility code
  # auth = get_kb_item("/tmp/http/auth/" + port);
  # if (auth) parse_setcookie_header(header: auth - "Cookie:");

  if (isnull(req)) req = make_array();
  if (isnull(version))
  {
    v = get_kb_item('http/'+port);
    if (v == "")
      version = 11;
    else
      version = int(v);
  }
  else
    version = int(version);
  if (version < 9 || version > 11)
  {
    err_print('http_mk_req: invalid version: ', version, '\n');
    version = 11;
  }
  if (version >= 11 && isnull(host))
  {
    hn = get_kb_item('www/'+port+'/http11_hostname');
    if (! isnull(hn))
      host = hn;
    else
    {
      # SC3
      host = get_preference('sc.hostname.' + get_host_ip());
      if (strlen(host) == 0) host = get_host_name();
    }
  }
  h = make_array();
  h['$method'] = method; h['$uri'] = item; h['$port'] = port; 
  h['$version'] = version; 
  if (version <= 9)
  {
    # Note that only GET is valid
    h['$request'] = strcat(method, ' ', item);
    h['$data'] = data;
    # We do not copy the headers
    return h;
  }
  if (version == 10) req = strcat(method, ' ', item, ' HTTP/1.0');
  else
  {
    req = strcat(method, ' ', item, ' HTTP/1.1');
    h['Host'] = host;
  }

  v = get_kb_item("global_settings/http_user_agent");
  if (! v) v = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)';
  h['User-Agent'] = v;

  h['Connection'] = 'Close';
  h['Pragma'] = 'no-cache';
  h['Accept'] = 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*';
  h['Accept-Language'] = 'en';
  h['Accept-Charset'] = 'iso-8859-1,utf-8;q=0.9,*;q=0.1';
  h['Cookie'] = mk_cookie_header(item: item);
  h['$request'] = req;
  if (! isnull(data))
  {
    h['$data'] = data;
    h['Content-Length'] = strlen(data);
  }

  if (! isnull(content_type)) h['Content-Type'] = content_type;

  if (typeof(add_headers) == "array")
    foreach k (keys(add_headers))
      h[k] = add_headers[k];

  return h;
}

function http_mk_get_req(port, host, item, version, data, add_headers)
{
  return http_mk_req( method: 'GET', port: port, host: host, item: item, 
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_head_req(port, host, item, version, data, add_headers)
{
  return http_mk_req( method: 'HEAD', port: port, host: host, item: item, 
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_trace_req(port, host, item, version, data, add_headers)
{
  return http_mk_req( method: 'TRACE', port: port, host: host, item: item, 
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_delete_req(port, host, item, version, data, add_headers)
{
  return http_mk_req( method: 'DELETE', port: port, host: host, item: item, 
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_post_req(port, host, item, version, data, add_headers, content_type)
{
  if (isnull(data))
    err_print('http_mk_post_req: no data parameter\n');
  return http_mk_req( method: 'POST', port: port, host: host, item: item, 
  	 	      content_type: content_type,
  	 	      version: version, data: data, add_headers: add_headers);
}

function http_mk_put_req(port, host, item, version, data, add_headers, content_type)
{
  if (isnull(data))
    err_print('http_mk_put_req: no data parameter\n');
  return http_mk_req( method: 'PUT', port: port, host: host, item: item, 
  	 	      content_type: content_type,
  	 	      version: version, data: data, add_headers: add_headers);
}

global_var	_nonceCount;

function http_mk_buffer_from_req(req, transport)
{
  local_var	buf, h, p, t;

  if (isnull(req))
  {
    err_print('http_mk_buffer_from_req: req parameter is not set\n');
    return NULL;
  }

  if (strlen(req['$request']) == 0)
  {
    err_print('http_mk_buffer_from_req: no request line\n');
    return NULL;
  }
  buf = strcat(req['$request'], '\r\n');
  if (! isnull(req['Host']))
  {
    buf = strcat(buf, 'Host: ', req['Host']);
    p = int(req['$port']);

    if (isnull(transport))
      transport = get_port_transport(p);

    if ((transport == ENCAPS_IP && p != 80) || (transport > ENCAPS_IP && p != 443))
      buf = strcat(buf, ':', p);
    buf += '\r\n';
  }
  foreach h (keys(req))
    if (h != 'Host' && h[0] != '$' && ! isnull(req[h]))
      buf = strcat(buf, h, ': ', req[h], '\r\n');

  if ( http_get_gzip_enabled() && isnull(req["Accept-Encoding"]) )
 	buf = strcat(buf, 'Accept-Encoding: gzip\r\n');

  buf = strcat(buf, '\r\n');
  if (strlen(req['$data']) > 0) buf = strcat(buf, req['$data']);
  return buf;
}

# Needed for NTLM

function ascii2utf16LE(ascii)
{
  local_var	i, len, r;

  len = strlen(ascii);
  r = "";
  for (i = 0; i < len; i ++)
    r = strcat(r, ascii[i], '\0');
  return r;
}

function LEword(blob, pos)
{
  return ord(blob[pos]) | (ord(blob[pos+1]) << 8);
}

function mkLEword()
{
 local_var l;
 l = _FCT_ANON_ARGS[0];
 return  raw_string(l & 0xff, (l >> 8) & 0xff);
}

function _rand64()
{
 return raw_string( rand() & 0XFF, rand() & 0XFF, rand() & 0XFF, rand() & 0XFF, 
 		    rand() & 0XFF, rand() & 0XFF, rand() & 0XFF, rand() & 0XFF);
}

function hexnumber(n)
{
 local_var	d, s, i;

 if (n < 0)
 {
   err_print('hexnumber: negative argument ', n);
   return NULL;
 }

 for (i = 0; i < 8; i ++)
 {
   d = n % 16;
   # 'a' = 97 
   if (d >= 10) d = raw_string(d + 87);
   s = strcat(d, s);
   n /= 16;
 }
 return s;
}

HTTP_AUTH_BASIC		= (1 << 0);
HTTP_AUTH_NTLM		= (1 << 1);
HTTP_AUTH_DIGEST	= (1 << 2);
HTTP_AUTH_KERBEROS	= (1 << 3);	# Negociate?

_allowed_HTTP_auth = ~0;	# Enable all by default

function http_disable_auth_scheme()
{
  local_var	prev;
  prev = _allowed_HTTP_auth;
  _allowed_HTTP_auth = _allowed_HTTP_auth & ~ (_FCT_ANON_ARGS[0]);
  return prev;
}

function http_enable_auth_scheme()
{
  local_var	prev;
  prev = _allowed_HTTP_auth;
  _allowed_HTTP_auth = _allowed_HTTP_auth | (_FCT_ANON_ARGS[0]);
  return prev;
}

# Examples:
# WWW-Authenticate: Basic realm="11.12.13.14/directory"
#

function http_add_auth_to_req(req, headers, username, password)
{
  local_var	auth, v, uri, realm, proxy, authR, hnc;
  local_var	ha1, ha2, resp, method, nonce, cnonce, qop, opaque, algo;
  local_var	msg, protocol, type, msg_len, flags, hostname, domain, user16;
  local_var	lm_resp_off, nt_resp_off, dom_len, user_len, host_len, user_off;
  local_var	host_off, nt_resp, lm_resp, h;
  local_var	try_basic;

  if (isnull(req))
  {
    err_print('http_add_auth_to_req: req parameter cannot be NULL\n');
    return NULL;
  }
  if (isnull(headers)) try_basic = 1;
  else
  {
    auth = egrep(pattern: "^WWW-Authenticate: *(Basic|Digest|NTLM)", string: headers, icase: 1);
    if (! auth)
    {
      auth = egrep(pattern: "^Proxy-Authenticate: *(Basic|Digest|NTLM)", string: headers, icase: 1);
      if (auth)
        proxy = 1;
      else
      {
        debug_print('http_add_auth_to_req: Neither WWW-Authenticate nor Proxy-Authenticate in headers\n');
	try_basic = 1;
      }
  }
  }
  # Make sure that egrep() and eregmatch() works simply
  if ( strlen(chomp(auth)) > 0 )
   auth = '\n' + str_replace(string: chomp(auth), find: '\r\n', replace: '\n') + '\n';

  if (isnull(username))
    username = get_kb_item("http/login");
  if (isnull(password))
    password = get_kb_item("http/password");
  if (strlen(username) == 0 && strlen(password) == 0)
  {
    debug_print(level: 2, 'No credentials!');
    return NULL;
  }

  # Basic authentication

  if (_allowed_HTTP_auth & HTTP_AUTH_BASIC)
  {
  if (! try_basic)
    v = eregmatch( string: auth, icase: 1,
      pattern: '\n(WWW|Proxy)-Authenticate: *Basic( +realm="([^"]*)")?');
  if (try_basic || ! isnull(v))
  {
    # realm = v[3];
    authR = strcat('Basic ', base64(str: strcat(username, ":", password)));
    if (proxy) req['Proxy-Authorization'] = authR;
    else req['Authorization'] = authR;
    return req;
  }
  }


  if (_allowed_HTTP_auth & HTTP_AUTH_NTLM)
    {
  # NTLM authentication
  # If keep alive is disabled, this will fail miserably
  # 1st message

  if (egrep(string: auth, pattern: '^(WWW|Proxy)-Authenticate: *NTLM *$'))
  {
     authR =
      strcat('NTLM ',
        base64(str: strcat(
          'NTLMSSP\x00', 
          '\x01\x00\x00\x00',		# 1: NTLMSSP_NEGOCIATE
# Negociate NTLM2, Negociate always sign, Negociate NTLM key, Request target,
# Negociate OEM, Negociate Unicode.
	  '\x07\x82\x08\x00',
	   '\0\0\0\0\0\0\0\0',		# Calling workstation domain
	   '\0\0\0\0\0\0\0\0' )));	# Calling workstation name
    if (proxy) req['Proxy-Authorization'] = authR;
    else req['Authorization'] = authR;
    return req;
  }

  # NTLM: next messages
  v = eregmatch( string: auth, 
      		 pattern: '\n(WWW|Proxy)-Authenticate: *NTLM +([A-Za-z0-9/+=]+) *\n' );
  if (! isnull(v))
  {
    msg = base64_decode(str: v[2]);
    protocol = substr(msg, 0, 7);
    if (protocol != 'NTLMSSP\0')
    {
      debug_print(level: 1, 'Unknown NTLM protocol: ', protocol);
      return NULL;
    }
    type = ord(substr(msg, 8, 8));
    if (type != 2)
    {
      debug_print(level: 1, 'Unknown NTLM type: ', type);
      return NULL;
    }

    # Type = 2
    # flags = substr(msg, 12, 13);
    msg_len = LEword(blob: msg, pos: 16);
    flags = LEword(blob: msg, pos: 20);
    nonce = substr(msg, 24, 31);

    # Build type 3 message
    domain = "";
    hostname = this_host_name();
    user16 = username;
    domain = ascii2utf16LE(ascii: toupper(string(domain))); 
    hostname = ascii2utf16LE(ascii: string(hostname));
    user16 = ascii2utf16LE(ascii: string(username));
    dom_len = strlen(domain);
    user_len = strlen(user16);
    host_len = strlen(hostname);
    user_off = 64 + dom_len;
    host_off = user_off + user_len;
    lm_resp_off = host_off + host_len;
    nt_resp_off = lm_resp_off + 0x18;
    msg_len = nt_resp_off + 0x18;
    # NTLM2
    cnonce = _rand64();
    lm_resp = strcat(cnonce, '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0');
    h = substr(MD5(strcat(nonce, cnonce)), 0, 7);
    nt_resp = HTTP_NTLM_Response(password: ascii2utf16LE(ascii: string(password)), challenge: h);
    nt_resp = nt_resp[0];
 
    msg = strcat( 'NTLMSSP\0', '\x03\x00\x00\x00',
    	  	  '\x18\x00', '\x18\x00', mkLEword(lm_resp_off), '\0\0', 
    	  	  '\x18\x00', '\x18\x00', mkLEword(nt_resp_off), '\0\0',
		  mkLEword(dom_len), mkLEword(dom_len), 
		  '\x40\x00', '\0\0',	# domain offset
		  mkLEword(user_len), mkLEword(user_len), 
		  mkLEword(user_off), '\0\0',
		  mkLEword(host_len), mkLEword(host_len), 
		  mkLEword(host_off), '\0\0',
		  '\0\0\0\0',
		  '\0\0\0\0',
		  '\x05\x82\x08\x00',
		  domain,
		  user16,
		  hostname,
		  lm_resp,
		  nt_resp );
    authR = strcat('NTLM ', base64(str: msg));
    if (proxy) req['Proxy-Authorization'] = authR;
    else req['Authorization'] = authR;
    return req;
  }
  }

  # Digest authentication - does not work on some IIS versions
  if (_allowed_HTTP_auth & HTTP_AUTH_DIGEST)
  {
#==========+==========+==========================================+
#    qop   |algorithm |               response                   |
#==========+==========+==========================================+
#    ?     |  ?, md5, | MD5(MD5(A1):nonce:MD5(A2))               |
#          | md5-sess |                                          |
#--------- +----------+------------------------------------------+
#   auth,  |  ?, md5, | MD5(MD5(A1):nonce:nc:cnonce:qop:MD5(A2)) |
# auth-int | md5-sess |                                          |
#==========+==========+==========================================+
#    qop   |algorithm |                  A1                      |
#==========+==========+==========================================+
#          | ?, md5   | user:realm:password                      |
#----------+----------+------------------------------------------+
#          | md5-sess | MD5(user:realm:password):nonce:cnonce    |
#==========+==========+==========================================+
#    qop   |algorithm |                  A2                      |
#==========+==========+==========================================+
#  ?, auth |          | req-method:req-uri                       |
#----------+----------+------------------------------------------+
# auth-int |          | req-method:req-uri:MD5(req-entity-body)  |
#=====================+==========================================+
  v = eregmatch( string: auth, icase: 1,
      		 pattern: '\n(WWW|Proxy)-Authenticate: *Digest (.*,)? *realm="([^"]*)"');
  if (! isnull(v))
  {
    realm = v[3];
    debug_print(level:4, 'http_add_auth_to_req: Digest realm=', realm);
    uri = req['$uri'];    
    v = eregmatch( string: auth, icase: 1,
      		 pattern: '\n(WWW|Proxy)-Authenticate: *Digest .*, *nonce="([^"]+)"');
    if (isnull(v))
    {
      debug_print(level: 1, "Cannot extract nonce\n");
      return NULL;
    }
    nonce = v[2];
    debug_print(level:4, 'http_add_auth_to_req: Digest nonce=', nonce);
    v = eregmatch( string: auth, icase: 1,
      		 pattern: '\n(WWW|Proxy)-Authenticate: *Digest .*, *algorithm=([^,]+)');
    if (! isnull(v))
      algo = v[2];
    else
      algo = "MD5";
    debug_print(level:4, 'http_add_auth_to_req: Digest algo=', algo);

    ha1 = MD5(strcat(username, ':', realm, ':', password));
    if ( 'qop=' >!< auth) # qop unspecified - RFC 2069
      qop = NULL;
    else if (egrep(string: auth, pattern: '^(WWW|Proxy)-Authenticate: *Digest (.*,)? *qop="([^"]+,)?auth[,"]'))	# qop=auth
      qop = 'auth';
    else
    {
      debug_print(level: 1, "auth-int Not handled yet\n");
      # We need to hash the entire response body
      return NULL;
    }

    uri = req['$uri'];
    method = req['$method'];
    ha2 = MD5(strcat(method, ':', uri));

    _nonceCount ++;
#    cnonce = str_replace(string: strcat(gettimeofday(), '.', rand()), find: '.', replace: '=');
    cnonce = strcat(gettimeofday(), '.', rand());
    hnc = hexnumber(n: _nonceCount);

    if (tolower(algo) == 'md5-sess') {
      #rfc 2617 Errata ID: 1649
      #ha1 needs to be hexstr
      ha1 = MD5(strcat(hexstr(ha1), ':', nonce, ':', cnonce));
    }

    ha1 = hexstr(ha1); ha2 = hexstr(ha2);

    if (qop == 'auth' || qop == 'auth-int')
      resp = MD5(strcat(ha1, ':', nonce, ':', hnc, ':', cnonce, ':', qop, ':', ha2));
    else if (qop == '')
      resp = MD5(strcat(ha1, ':', nonce, ':', ha2));
    else
    {
      err_print('http_add_auth_to_req: unhandled qop=', qop, '\n');
      return NULL;
    }
    resp = hexstr(resp);

    if (qop == '')
      authR =
      strcat('Digest username="', username, '", realm="', realm, '", nonce="', nonce, '", uri="', uri, '", cnonce="', cnonce, '", algorithm=', algo, ', response="', resp, '"');
    else 
      authR = 
      strcat('Digest username="', username, '", realm="', realm, '", nonce="', nonce, '", uri="', uri, '", algorithm=', algo, ', response="', resp, '", qop=', qop, ', nc=', hnc, ', cnonce="', cnonce, '"');
    v = eregmatch( string: auth, icase: 1,
      		 pattern: '\n(WWW|Proxy)-Authenticate: *Digest .*, *opaque="([^"]*)"');
    if (! isnull(v))
    {
      opaque = v[2];
      authR = strcat(authR, ',opaque="', opaque, '"');
      debug_print(level:4, 'http_add_auth_to_req: Digest opaque=', opaque);
    }
    if (proxy) req['Proxy-Authorization'] = authR;
    else       req['Authorization'] = authR;
    return req;
  }
  }

  # Unknown authentication method?

  debug_print(level: 1, 'Unsupported HTTP authentication method: ', auth);
  return NULL;
}

