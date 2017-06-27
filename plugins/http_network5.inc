# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# http_network5.inc
# $Revision: 1.5 $

global_var __ka_socket, __ka_port, __ka_enabled, __ka_last_request, __ka_transport, __ka_pid;
global_var __http_read_timeout, __http_incr_timeout_on_err, __http_sent_request;
global_var _basic_auth_URLs, __http_error_port, __http_error_op, __http_error_code;
global_var __http_use_async_sock, _in__http_set_error, __http_recv_body_cb;
global_var __redirect_with_get; # 0: RFC compliant / 1: broken but common

__os = NULL;
__ka_socket = NULL;
__ka_port   = 0;
__ka_enabled = -1;
__ka_last_request = "";
__ka_pid = NULL;

_in__http_set_error = 0;
__http_read_timeout = NULL;
__http_incr_timeout_on_err = 1;
__http_sent_request = NULL;
__redirect_with_get = 1;
_http_max_req_sz = 1048576;

__http_recv_body_cb = NULL;

##
# the main connection function. This is accessed through
# other functions to init the connection to server
#
# @param [target:string] ip address of non standard system
# @param [port:int] port of target
# @param [transport:string] transport type, default ENCAPS_IP
# @return [socket object] socket to return for query
##
function http_open_sock_err(target, port, transport)
{
  local_var s, e, now, t1, t2, to, dt, rto;

  t1 = gettimeofday();
  if (target)
  {
    s = open_sock2(host:target, port:port, timeout:__http_read_timeout, transport:ENCAPS_IP);
    if ( s && !isnull(transport) && transport != ENCAPS_IP )
    {
      s = socket_negotiate_ssl(socket:s, transport:transport);
    }
  }
  else
  {
    s = open_sock_tcp(port, transport: transport, timeout: __http_read_timeout);
  }
  if (s)
  {
    # http_clear_error(port: port);
    return s;
  }
  # Error
  t2 = gettimeofday();
  now = split(t2, sep: '.', keep: 0);
  now = int(now[0]);
  to = http_get_read_timeout();
  dt = difftime(t1: t1, t2: t2);
  if (dt < to *1000000 - 500000)
  {
    if (defined_func("socket_get_error") && __http_use_async_sock)
    {
      if (target)
      {
        s = open_sock2(host:target, port:port, timeout:__http_read_timeout, transport:ENCAPS_IP);
        if ( s && !isnull(transport) && transport != ENCAPS_IP )
        {
          s = socket_negotiate_ssl(socket:s, transport:transport);
        }
      }
      else
      {
        s = open_sock_tcp(port, transport: transport, nonblocking:TRUE, timeout: __http_read_timeout);
      }
      while (1)
      {
        if (socket_ready(s))
        {
          e = socket_get_error(s);
          if (e == 0)
          {
            debug_print('http_open_sock_err: connection to TCP port ', port, ' succeeded on 2nd attempt.');
            # http_clear_error(port: port);
            return s;
          }
          else
          {
            close(s);
            now = unixtime();
            break;
          }
       }
        sleep(1);
      }
      #NOTREACHED
    }
    else
    {
       e = ECONNREFUSED;   
    }
  }
  else
  {
    e = ETIMEDOUT;
  }

  debug_print('http_open_sock_err: connection to TCP port ', port, ' failed - errno=', e);
  http_set_error(target: target, port: port, errno: e, op: 'connecting to server');
  return NULL;
}

##
# clear error handlers for globals
#
# @param [port:int] port to clear with target
# @return [NULL]
##
function http_clear_error(port)
{
  __http_error_code = NULL;
  __http_error_op = NULL;
  __http_error_port = NULL;
  rm_kb_item(name:'www/'+port+'/unresponsive/time');
  rm_kb_item(name:'www/'+port+'/unresponsive/nb');
 _in__http_set_error = 0;
}

##
# error report handling for http type sockets
# 
# @param [port:int] port with error status
# @param [socket:object] socket object with error
# @param [op:string] details of what happened while error
# @param [errno:string] error information
# @param [now:time] current time of error
# @return [NULL]
##
function http_set_error(target, port, socket, op, errno, now)
{
  local_var dead_time, dead_nb, v, to, to2;

  if (_in__http_set_error)
  {
    debug_print('http_set_error: recursive call aborted!\n');
    return;
  }
  _in__http_set_error = 1;
  
  if (isnull(port))
  {
    if (isnull(socket))
    {
      err_print('http_set_error: port or socket argument missing.\n');
      _in__http_set_error = 0;
      return;
    }
    v = get_sock_name(socket);
    if (isnull(v))
    {
      debug_print('http_set_error: get_sock_name(', socket, ')=NULL\n');
      _in__http_set_error = 0;
      return;
    }
    port = v[1];
  }
  if (isnull(errno) && ! isnull(socket))
    errno = socket_get_error(socket);

  debug_print('http_set_error: port=', port, ' errno=', errno, ' (', http_strerror(errno), '), op=', op, '\n');
  __http_error_code = errno;
  __http_error_op = op;
  __http_error_port = port;

  if (__http_incr_timeout_on_err && errno == ETIMEDOUT)
  {
    to = http_get_read_timeout();
    if (to < 30)
    {
      to ++;
      to2 = get_kb_item('www/'+port+'/read_timeout');
      if (to > to2)
      {
        http_set_read_timeout(to);
        debug_print(level: 1, 'http_set_error: increasing network timeout to ', to, ' s after ETIMEDOUT\n');
        if (port > 0) replace_kb_item(name: 'www/'+port+'/read_timeout', value: to);
      }
      else
      {
        http_set_read_timeout(to2);
      }
    }
  }

  if (isnull(now)) now = unixtime();
  dead_time = get_kb_item('www/'+port+'/unresponsive/time');
  dead_nb = get_kb_item('www/'+port+'/unresponsive/nb');
  dead_nb ++;
  replace_kb_item(name: 'www/'+port+'/unresponsive/nb', value: dead_nb);

  if (dead_time > 0)
  {
    if (now - dead_time >= 300 && dead_nb >= 20)
    {
      rm_kb_item(name:'www/'+port+'/unresponsive/time');
      rm_kb_item(name:'www/'+port+'/unresponsive/nb');
      if (http_is_dead(target:target, port:port))
        declare_broken_web_server(port: port, reason:
        'The web server failed to respond at least ' + dead_nb + ' times for ' + (now - dead_time) + ' s.');
    }
  }
  else
  {
    replace_kb_item(name: 'www/'+port+'/unresponsive/time', value: now);
  }
  _in__http_set_error = 0;
}

##
# return the error message in string format
#
# @return [string] error message information
##
function http_error_msg()
{
  if (isnull(__http_error_code) || isnull(__http_error_op))
    return NULL;

  return __http_error_op + ': errno=' + __http_error_code + ' (' +
         http_strerror(__http_error_code) + ')';
}

##
# error status types
#
# @param [_FCT_ANON_ARGS[0]:int] report info?
# @return [string] error type details
##
function http_strerror()
{
  local_var e;

  e = int(_FCT_ANON_ARGS[0]);

  if (e == NOERR) return "no error";
  if (e == ETIMEDOUT) return "operation timed out";
  if (e == ECONNRESET) return "connection reset by peer";
  if (e == EUNREACH) return "host unreachable";
  if (e == EUNKNOWN) return "unknown error";
  if (e == ESSL) return "SSL error";
  if (e == EINPROGRESS) return "operation in progress";
  if (e == ECONNREFUSED) return "connection refused";
  if (e == ENOBUFS) return "no buffer space available";
  return "error #"+e;
}

##
# writer please write a brief intent of this function
# 
# @return [int] 
##
function http_transient_error()
{
  if ( __http_error_code == EINPROGRESS ||
       __http_error_code == ETIMEDOUT ||
       __http_error_code == ENOBUFS )
    return 1;
  if (__http_error_code == ECONNREFUSED)
  {
    if (get_kb_item('Port/tcp/'+__http_error_port))
    {
      if (isnull(__os)) __os = get_kb_item("Host/OS");
      if (!isnull(__os) && "Windows" >< __os)
        return 1;
    }
  }
  return 0;
}

##
# recv the header from a http socket
# this function will also parse the cookie
#
# @param [socket:string] socket to recv the header from
# @return [string]
##
function http_recv_headers3(target, socket)
{
  local_var buf, line, counter;

  buf = NULL;
  while ( TRUE )
  {
    counter ++;
    line = recv_line(socket:socket, length:4096, timeout: __http_read_timeout);
    if (strlen(line) == 0) break;
    buf = strcat(buf, line);
    if (line =~ '^Set-Cookie2?:') parse_setcookie_header(header: line);
    if ( line == '\r\n' || line == '\n') break;
    if ( counter > 1024 ) break;
  }
  if (isnull(buf))
  {
    debug_print('http_recv_headers3: cannot read HTTP headers\n');
    http_set_error(target: target, socket: socket, op: 'reading HTTP headers');
  }
  return buf;
}

##
# Compatibility function
#
# @return [socket object]
##
function http_recv_headers2(target, socket)
{
  return http_recv_headers3(target: target, socket: socket);
}

##
# disable the keep alive status on http messages
# and disable and sockets with keep alive status
#
# @return [NULL]
##
function http_disable_keep_alive()
{
  __ka_enabled = 0;
  if (__ka_socket > 0)
  {
    http_close_socket(__ka_socket);
    __ka_socket = NULL;
  }
}

##
# enable keep alive global var
#
# @return [NULL]
##
function http_enable_keep_alive()
{
  if (!__ka_enabled) __ka_enabled = -1;
}

##
# force the keep alive status to stay active
#
# @param [port:int] 
# @return [NULL]
##
function http_force_keep_alive(port)
{
  if (__ka_socket > 0 && __ka_port != port)
  {
    http_close_socket(__ka_socket);
    __ka_socket = NULL;
    __ka_pid = NULL;
  }
  __ka_enabled = 1;
  __ka_port = port;
}

##
# Initialize a socket or reopen a keep alive socket
#
# @param [target:string] ip address of non standard system
# @param [socket:object] socket to reopen if exists
# @param [port:int] port of the socket to open
# @param [keepalive:BOOL] turn on keep alive status or NULL
# @param [transport:string] transport type, default ENCAPS_IP
# @return [socket object]
##
function http_reopen_socket(target, socket, port, keepalive, transport)
{
  if (socket)
  {
    if (socket == __ka_socket) __ka_socket = NULL;
    __ka_pid = NULL;
    http_close_socket(socket);
  }

  socket = http_open_sock_err(target: target, port: port, transport: transport);

  if (keepalive)
  {
    __ka_socket = socket; __ka_port = port; __ka_transport = transport;
    if ( defined_func("getpid") ) __ka_pid = getpid();
  }
  return socket;
}

##
# maintain the keep alive socket checking the params of 
# the global vars to confirm they are valid
#
# @param [target:string] ip address of non standard system
# @param [port:int] port of the socket to open
# @param [keepalive:BOOL] turn on keep alive status or NULL
# @param [transport:string] transport type, default ENCAPS_IP
#
# @return [socket object]
##
function http_open_socket_ka(target, port, keepalive, transport)
{
  if (__ka_socket && keepalive && __ka_port == port && __ka_transport == transport)
 {
    if ( !defined_func("getpid") || __ka_pid == getpid() ) return __ka_socket;
 }
  return http_reopen_socket(target: target, socket: __ka_socket, port: port, keepalive: keepalive, transport: transport);
}

##
# close a socket and return the keep alive globals
# to NULL status
#
# @param [_FCT_ANON_ARGS[0]:object] keep alive socket object to close
# @return [NULL]
##
function http_close_socket_ka()
{
  local_var s;
  s = _FCT_ANON_ARGS[0];
  http_close_socket(s);
  if (s == __ka_socket)
  {
    __ka_socket = NULL;
    __ka_port = NULL;
    __ka_pid = NULL;
  }
}

##
# disable the keep alive status from globals
#
# @param [_FCT_ANON_ARGS[0]:object] keep alive socket object to disable
# @return [NULL]
##
function disable_socket_ka()
{
  local_var s;
  s = _FCT_ANON_ARGS[0];
  if (s == __ka_socket) __ka_socket = NULL;
}

##
# only close the socket if it is a keep alive socket and
# return the keep alive globals to NULL
#
# @param [_FCT_ANON_ARGS[0]:object] keep alive socket object to close
# @return [NULL]
##
function _http_close_socket_ka_only()
{
  local_var    s;
  s = _FCT_ANON_ARGS[0];
  if (s != __ka_socket) return;
  http_close_socket(s);
  __ka_socket = NULL;
  __ka_port = NULL;
  __ka_transport = NULL;
}

##
# check the header if it has connection close status
# and if it does reopen socket
#
# @param [header:string] packet header
# @return [NULL]
##
function http_keepalive_check_connection(headers)
{
  local_var tmp;
  tmp = egrep(pattern:"^Connection: *Close", string:headers, icase: 1);
  if(tmp)
  {
     if ( __ka_socket ) http_close_socket(__ka_socket);
     __ka_socket = http_open_sock_err(port: __ka_port);
  }
}

##
# enable the global keep alive variable and 
# open a socket with the keep alive socket object
# set to the global variable __ka_socket
#
# @param [port:int] port to open
# @param [transport:string] transport type, default ENCAPS_IP
# @return [NULL]
##
function enable_keepalive(target, port, transport)
{
  __ka_enabled = 1;
  __ka_port    = port;
  __ka_socket  = http_open_sock_err(target: target, port: port, transport: transport);
  if ( defined_func("getpid") ) __ka_pid = getpid();
  __ka_transport = transport;
  if ( defined_func("getpid") ) __ka_pid	= getpid();
}

##
# set keep alive status to true for port and test. If tests
# are possitive response then
# replace_kb_item(name:strcat("www/", port, "/keepalive"), value:"yes");
#
# @param [target:string] ip address of non standard system
# @param [port:int] port to test and set status for keep alive
# @param [exit_on_fail:BOOL] exit if failures, default FALSE
# @param [transport:string] transport type, default ENCAPS_IP
# @return [int] 0 ka no|| 1 success|| -2 fail
#
# @note keep-Alive is necessary for NTLM authentication, so we 
#   try to have it even on a LAN.
##
function http_keepalive_enabled(target, port, exit_on_fail, transport)
{
  local_var rq, buf, soc, r, b, kb, host;
  
  if ( !isnull(target) )
  {
    kb = get_kb_item(strcat("www/", port, "/keepalive"));
    
    if ( !isnull(target) )
    {
      enable_keepalive(target:target, port: port, transport: transport);
      return 1;
    }
    
    if (kb == "yes")
    {
      enable_keepalive(target:target, port: port, transport: transport);
      return 1;
    }
    else if (kb == "no") return(0);
  }
 
  # keep-Alive is necessary for NTLM authentication, so we try to have it
  # even on a LAN.

  host = get_preference('sc.hostname.' + get_host_ip()); # SC3
  
  if (strlen(host) == 0) host = get_host_name();
 
  rq = http_mk_get_req( port: port, host: host, item: "/", version: 11);
  rq['Pragma'] = 'no-cache';
  rq['Connection'] = 'Keep-Alive';
  if (target) rq['Host'] = target;

  soc = http_open_sock_err(target: target, port: port, transport: transport);
  if(!soc)
    if (exit_on_fail) exit(1, "Cannot connect to TCP port "+port+".");
    else  return -2;
 
  buf = http_mk_buffer_from_req(req: rq, transport: transport);
  send(socket:soc, data: buf);
  r = http_recv_headers3(target: target, socket: soc);

  if (isnull(r))
  {
    http_close_socket(soc);
    if (exit_on_fail) exit(1, "Cannot read HTTP headers on port "+port+".");
    return -2;
  }
  b = http_recv_body(target: target, socket: soc, headers: r);

  # Apache
  if(egrep(pattern:"^Keep-Alive:.*", string:r))
  {
    http_close_socket(soc);
    if ( isnull(target) ) replace_kb_item(name: strcat('www/', port, '/keepalive'), value:"yes");
    enable_keepalive(target: target, port:port, transport: transport);
    return 1;
  }
  else if ( egrep(pattern: "^Server: *Microsoft-IIS", string: r) || 
            egrep(pattern:"^Connection: *Keep-Alive", string:r, icase: 1))
  {
    # IIS
    if (send(socket:soc, data: buf) == strlen(buf))
    {
      r = _http_recv(target: target, socket:soc);
      http_close_socket(soc);
      if (strlen(r) > 0)
      {
        if ( isnull(target) ) replace_kb_item(name:strcat("www/", port, "/keepalive"), value:"yes");
        enable_keepalive(target: target, port:port, transport: transport);
        return 1;
      }
    }
  }

  if ( isnull(target) ) replace_kb_item(name:strcat("www/", port, "/keepalive"), value:"no");
  return 0;
}

##
# encode none standard characers with url encode
#
# @param [str:string] string to encode
# @param [unreserved:string] standard string items to not encode
# @return [string]
##
function redir_urlencode(str, unreserved)
{
  local_var ch, estr, len, i;

  estr = "";
  len = strlen(str);
  if (isnull(unreserved)) unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]";

  for (i=0; i<len; i+=1)
  {
    ch = str[i];

    if (ch >< unreserved) estr += ch;
    # the rest are escaped.
    else
    {
      ch = hexstr(ch);
      ch = toupper(ch);
      estr += "%" + ch;
    }
  }

  return estr;
}

##
# parse the string url sent in and encode it
# with url encoding if needed
#
# @param [item:string] url to encode
# @return [string]
##
function fix_rel_location(item)
{
  local_var i, path, qs, prev;

  i = stridx(item, '?');
  if (i < 0)
  {
    path = item;
    qs = NULL;
  }
  else if (i == 0)
  {
    path = "";
    qs = substr(item, 1);
  }
  else
  {
    path = substr(item, 0, i - 1);
    qs = substr(item, i + 1);
  }

  # Remove sharp, we do not need it, it is interpreted by the browsers only
  if (qs)
  {
    i = stridx(qs, '#');
    if (i >= 0) qs = substr(qs, 0, i - 1);
  }

  if (! ereg(string: path, pattern: "^([/a-zA-Z0-9_.!~*'()-]|(%[0-9a-fA-F]{2}))*$"))
    path = redir_urlencode(str: path, unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-/");

  # Mind the + & = [ ]
  if (! isnull(qs) && 
      ! ereg(string: qs, pattern: "^([/a-zA-Z0-9_.!~*'()&+=\[\]-]|(%[0-9a-fA-F]{2}))*$"))
    qs = redir_urlencode(str: qs, unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-[]/&+=");


  prev = item;
  if (isnull(qs)) item = path;
  else item = strcat(path, '?', qs);
  debug_print(level:2, 'fix_rel_location: ', prev, ' -> ', item, '\n');
  return item;
}

##
# Sends and recv a http response. This should be called from higher
# level functions and not directly
#
# @param [port:int] port to connect to
# @param [only_content:BOOL] This is mainly used by webmirror.nasl
# @param [no_body:BOOL] false if body is empty
# @param [exit_on_fail:BOOL] exit if fails default false
# @param [transport:string] transport type, default ENCAPS_IP
# @return [string] request response
##
function _http_send_recv_once(target, port, buf, req, ka, fetch404, only_content, no_body, follow_redirect, exit_on_fail, username, password, transport)
{
  local_var s, r, status_line, headers, body, ct, head;
  local_var no403, v, e, count;
  local_var line,w,newuri,ver,z,newreqline,auth,newport;

  s = http_open_socket_ka(target:target, port: port, keepalive: ka, transport: transport);
  if (!s)
  {
    debug_print('_http_send_recv_once(port: ', port, '): http_open_socket_ka failed\n');
    if (exit_on_fail)
      exit(1, "Can't connect to web server on port "+port+".");
    else
      return NULL;
  }

  head = 0;
  if (isnull(buf))
  {
    if (isnull(req))
    {
      err_print('_http_send_recv_once: buf and req paramaters cannot both be NULL\n');
      if (exit_on_fail)
        exit(1, "Invalid parameters for _http_send_recv_once(port=", port, ").");
      return NULL;
    }
    else
    {
      if (ka)
        req['Connection'] = 'Keep-Alive';
      else if (req['$version'] != 9)
        req['Connection'] = 'Close';
      if (req['$method'] == 'HEAD') head = 1;
      buf = http_mk_buffer_from_req(req: req, transport: transport);
    }
  }
  else
  {
    if (! isnull(req))
    {
      err_print('_http_send_recv_once: buf and req paramaters cannot both be set. req ignored.\n');
    }
    if (match(string: buf, pattern: "HEAD *")) head = 1;
  }

  r = send(socket: s, data: buf);
  if (r > 0)
  {
    __http_sent_request = buf;

    # status lines and headers do not exist in HTTP 0.9
    if (req['$version'] == 9)
    {
      v = make_list();
      v[0] = NULL;  # no status line
      v[1] = NULL;  # no headers
      v[2] = NULL;  # body

      repeat
      {
        body = recv_line(socket: s, length: 4096, timeout: __http_read_timeout);
        v[2] += body;
      } until isnull(body);

      http_close_socket_ka(s);
      return v;
      # never reached
    }

    status_line = recv_line(socket: s, length: 4096, timeout: __http_read_timeout);
    if (strlen(status_line) == 0)
    {
      e = socket_get_error(s);
      debug_print('_http_send_recv_once(port: ', port, '): cannot read status line - errno=', e, '\n');
      http_set_error(target: target, port: port, errno: e, op: 'reading the HTTP status line');
    }
  }
  else
  {
    debug_print('_http_send_recv_once(port: ', port, '): send failed\n');
    if (! ka)
    {
      e = socket_get_error(s);
      http_set_error(target: target, port: port, errno: e, op: 'sending the request');
    }
    status_line = NULL;
  }

  if (! status_line && ka)
  {
    s = http_reopen_socket(target: target, socket: s, port: port, keepalive: 1, transport: transport);
    if (! s)
    {
      debug_print('_http_send_recv_once(port: ', port, '): http_reopen_socket failed\n');
      if (exit_on_fail)
        exit(1, "Can't connect to web server on port "+port+".");
      else
        return NULL;
    }
    debug_print(level: 2, '_http_send_recv_once: socket to port ', port, ' reopen\n');
    r  = send(socket: s, data: buf);
    if (r > 0)
    {
      __http_sent_request = buf;
      status_line = recv_line(socket: s, length: 4096, timeout: __http_read_timeout);
      if (strlen(status_line) == 0)
      {
        e = socket_get_error(s);
        debug_print('_http_send_recv_once(port: ', port, '): cannot read status line - errno=', e, '\n');
        http_set_error(target: target, port: port, errno: e, op: 'reading the status line');
      }
    }
    else
    {
      status_line = NULL;
      debug_print('_http_send_recv_once(port: ', port, '): send failed\n');
      e = socket_get_error(s);
      http_set_error(target: target, port: port, errno: e, op: 'sending the request');
    }
  }

  if (strlen(status_line) == 0)
  {
    http_close_socket_ka(s);
    if (exit_on_fail)
      exit(1, "Can't read line from web server on port "+port+".");
    return NULL;
  }

  headers = http_recv_headers3(target: target, socket: s);

  # MA 2009-07-23: we cannot do anything very smart if we get a code and no
  # headers. The connection was probably broken. Let's return an error now.
  if (isnull(headers))
  {
    debug_print('_http_send_recv_once(port: ', port, '): cannot read headers\n');
    http_close_socket_ka(s);
    if (exit_on_fail)
      exit(1, "Can't read HTTP headers from web server on port "+port+".");
    return NULL;
  }

  #### Fix for very broken servers
  if (status_line =~ "<h[1-9]> *Bad Request.*</h[1-9]>")
  {
    debug_print('Broken server sent an invalid code : ', chomp(status_line));
    status_line = 'HTTP/1.0 400 Bad Request (broken server)\r\n';
  }
  # Add more error messages here
  ####

  #### 100 Continue ####
  if (status_line =~ '^HTTP/1\\.[01] +100 ')
  {
    # Keep last answer in case something fails...
    v = make_list(status_line, headers);

    status_line = recv_line(socket: s, length: 4096, timeout: __http_read_timeout);
    if (! status_line)
    {
      debug_print(level: 1, '_http_send_recv_once(port=', port, '): Cannot read status line after 100 Continue\n');
      http_set_error(target: target, port: port, socket: s, op: 'reading the status line');
      return v;
    }
    v = NULL;
    headers = http_recv_headers3(target: target, socket: s);
    if (isnull(headers))
    {
      debug_print(level: 1, '_http_send_recv_once(port=', port, '): Cannot read HTTP headers after 100 Continue\n');
      return make_list(status_line);
    }
  }

  # Start of redirection
  while (status_line =~ '^HTTP/1\\.[01] +30[1237] ' && follow_redirect > 0)
  {
    count = 0;
    while(recv(socket:s, length:2048,timeout:2))
    {
      count ++;
      if (count > 4) return NULL;
      continue;
    }

    follow_redirect --;
    line = egrep(string: headers, pattern: '^Location:', icase: 1);
    # 30x without Location header cannot be processed further
    if (strlen(line) == 0) return make_list(status_line, headers);
    # 307 force redirection with the same method; 303 redirects with GET
    # According to RFCs, 301/302 should behave like 307 but many browsers
    # implemented them like 303.
    if (status_line =~ '^HTTP/1\\.[01] +303 ' ||
        (status_line =~ '^HTTP/1\\.[01] +30[12] ' && __redirect_with_get))
    {
      req['$method'] = "GET";
      req['$data'] = NULL;
      req['Content-Length'] = NULL;
      req['Content-Type'] = NULL;
    }
    # Set the Referer, this might be important
    req['Referer'] = build_url(port: port, qs: req['$uri']);
    w = eregmatch(string: chomp(line), pattern: '^Location:[ \t]*([^ \t].*)', icase: 1);
    if (isnull(w))
    {
      debug_print("Invalid Location field: ", line);
      newuri = '';
    }
    else
      newuri = chomp(w[1]);

    if (req['$version'] == 9) ver = '';
    else if (req['$version'] == 10) ver = ' HTTP/1.0';
    else ver = ' HTTP/1.1';

    if (newuri !~ "^https?://")
    {
      debug_print(level: 2, "Redirection to relative URI is not RFC-compliant. Trying to fix it: ", newuri);
      newuri = fix_rel_location(item: newuri);
      # The RFC are clear but too many sites are broken
      if (req['$method'] == 'POST')
      {
        debug_print(level: 2, 'Switching from POST to GET to follow non RFC compliant redirection\n');
        req['$method'] = 'GET';
        req['$data'] = NULL; req['Content-Length'] = NULL; req['Content-Type'] = NULL; 
      }
      if (strlen(newuri) == 0 || newuri[0] != '/')
      {
        z = eregmatch(string: req['$uri'], pattern: "^(.*/)[^/]*$");
        if (isnull(z))
          debug_print("Cannot extract base directory from original URI: ", req['$uri']);
        else
          newuri = strcat(z[1], newuri);
      }
      req['$uri'] = newuri;
      newreqline = strcat(req['$method'], ' ', newuri, ver);
      req['Cookie'] = mk_cookie_header(item: newuri);
    }
    else
    {
      req['$uri'] = newuri; # Informative only
      debug_print(level: 3, 'Location=', w[1], '\n');
      w = eregmatch(string: newuri, pattern: 'https?://(([^/]+)@)?([^/:]+)?(:[0-9]+)?(/.*)', icase: 1);
      debug_print(level: 4, 'w=', w, '\n');
      if (isnull(w))
      {
        debug_print("Cannot parse Location: ", chomp(newuri));
        return make_list(status_line, headers);    # Cannot parse Location, won't go further
      }
      req['Host'] = w[3];
      if (target) req['Host'] = target;

      if (strlen(req['$scheme']) > 0) # This is a proxy request
      {
        newreqline = strcat(req['$method'], ' ', newuri, ver);
        req['Cookie'] = mk_cookie_header(item: newuri);
      }
      else
      {
        if (w[2]!= '')
        {
          auth = split(w[2], sep: ':', keep: 0);
          username = auth[0];
          if (auth[1] != '') password = auth[1];
        }
        if (strlen(w[4]) > 0)
        {
          newport = int(substr(w[4], 1));
          # We won't connect to the new port, this would lead to bogus reports
          if (newport != port) return make_list(status_line, headers);
        }
        newreqline = strcat(req['$method'], ' ', w[5], ver);
        req['Cookie'] = mk_cookie_header(item: w[5]);
      }
    }
    req['$request'] = newreqline;
    debug_print(level: 3, 'newreqline=', newreqline, '\n');
    v = _http_send_recv_once( target: target, port: port, req: req, ka: ka, fetch404: fetch404,
                              only_content: only_content, no_body: no_body, 
                              transport: transport, follow_redirect: follow_redirect,
                              exit_on_fail: exit_on_fail );
    if (isnull(v))
    {
      debug_print('http_send_recv_req(port: ', port, '): _http_send_recv_once failed - method=', req['$method'], ' item=', req['$uri'], ' port=', req['$port'], ' version=', req['$version'], '\n');
      return NULL;
    }
    debug_print(level: 3, 'v=', v, '\n');

    return v;
  }
  # End of redirection

  # Start of Auth
  no403 = get_kb_item('www/no403header/'+port);
  if ( strlen(no403) > 0 && egrep(string: headers, pattern: no403, icase: 1))
  {
    status_line = ereg_replace(string: status_line, pattern: "^HTTP/(1\.[01]) +([1-3][0-9][0-9]) ",
     replace: "HTTP/\1 403 ");
  }

  if (status_line =~ '^HTTP/1\\.[01] +40[17] ')
  {
    body = http_recv_body(target: target, socket: s, headers: headers, status_line:status_line);

      if (_http_chk_header(req:req, header:'authorization'))
      {
        debug_print(level:2, '_http_send_recv_once(port: ', port, '): _http_send_recv_once Authorization set\n');
        return make_list(status_line, headers, body);
      }

    req = http_add_auth_to_req( req: req, headers: headers, username: username, password: password);
    if (isnull(req))
    {
      debug_print(level:2, 'http_send_recv_req(port: ', port, '): http_add_auth_to_req failed\n');
      return make_list(status_line, headers, body);
    }


    v = _http_send_recv_once(target: target,port: port, req: req, ka: ka,
                             fetch404: fetch404, exit_on_fail: exit_on_fail, username:username, password:password, 
                             transport: transport);

    if (isnull(v))
    {
      debug_print('http_send_recv_req(port: ', port, '): _http_send_recv_once failed\n');
      return NULL;
    }

    if ( v[0] =~ '^HTTP/1\\.[01] +40[17] ' &&
         egrep(string: v[1], pattern: '^(WWW|Proxy)-Authenticate: NTLM'))
    {
      req = http_add_auth_to_req( req: req, headers: v[1], username: username, password: password);
      if (isnull(req))
      {
        debug_print(level:2, 'http_send_recv_req(port: ', port, '): http_add_auth_to_req failed\n');
        return make_list(status_line, headers, body);
      }

      v = _http_send_recv_once(target: target, port: port, req: req, ka: ka, fetch404: fetch404, exit_on_fail: exit_on_fail, 
                               username:username, password:password, transport: transport);
      if (isnull(v))
      {
        debug_print('http_send_recv_req(port: ', port, '): _http_send_recv_once failed\n');
        return NULL;
      }
    }
    return v;
  }

  if ( v[0] =~ "^HTTP/1\.[01] +20[0-9] " && match(string: req['Authorization'], pattern: "Basic *"))
  {
    _basic_auth_URLs[req['$uri']] = 1;
  }
  # End of Auth

  if (no_body)
  {
    if (! head) http_close_socket_ka(s);
    http_clear_error(port: port);
    if ( ! isnull(headers) ) return make_list(status_line, headers);
    else return make_list(status_line);
  }

  if (only_content) # This is mainly used by webmirror.nasl
  {
    ct = egrep(pattern: "^Content-Type:", icase: 1, string: headers);
    if (strlen(ct) > 0 && 
        ! egrep(pattern: '^Content-Type:[ \t]*' + only_content, icase: 1, string: ct))
    {
      http_close_socket_ka(s);
      http_clear_error(port: port);
      return make_list(status_line, headers);
    }
  }

  if (egrep(pattern:"^Connection: *Close", string: headers, icase: 1))
  {
    ka = 0;
    disable_socket_ka(s); # Avoid a double close
  }

  body = NULL;
  if (fetch404 || status_line !~ '^HTTP/1\\.[01] +404 ')
  {
    body = http_recv_body(target: target, socket: s, headers: headers, status_line:status_line);
    if (isnull(body) && isnull(http_get_recv_body_callback()) && status_line =~ '^HTTP/1\\.[01] +200 ' && "GET " >< req['$request'])
    {
      debug_print('_http_send_recv_once: ', req['$request'], ' could not download HTTP body (port=', port, ')\n');
    }
  }

  if (ka && __ka_socket && !head && isnull(body))
    ka = 0; # Body was not read, we don't want the next request to read it.
  if (! ka) http_close_socket_ka(s);

  http_clear_error(port: port);
  if (isnull(body))
    return make_list(status_line, headers);
  else
  {
    no403 = get_kb_item('www/no403body/'+port);
    if ( strlen(no403) > 0 && 
         egrep(string: body, pattern: no403, icase: 1))
    {
      status_line = ereg_replace(string: status_line, pattern: "^HTTP/(1\.[01]) +([1-3][0-9][0-9]) ",
       replace: "HTTP/\1 403 ");
    }
    return make_list(status_line, headers, body);
  }
}

##
# base call for http request that will 
# branch into the working calls.
#
# @param [port:int] port to connect to
# @param [host:string] http host header status
# @param [method:string] http method (ie: GET|POST)
# @param [item:string] url in header
# @param [data:string] data to send in the body
# @param [version:string] http version number (ie:1.1|1.0)
# @param [add_header:array] items to add to header request
# @param [username:string] auth username for example http auth
# @param [password:string] auth password ^
# @param [fetch404:BOOL] Return 404 pages
# @param [only_content:BOOL] This is mainly used by webmirror.nasl
# @param [no_body:BOOL] false if body is empty
# @param [follow_redirect:int] maximum number of redirects to follow
# @param [content_type:???] ???
# @param [exit_on_fail:BOOL] exit if fails default false
# @param [transport:string] transport type, default ENCAPS_IP
# @return [string] request response
##
function http_send_recv3(target, port, host, method, item, data, version, add_headers, username, password, fetch404, only_content, no_body, follow_redirect, content_type, exit_on_fail, transport)
{
  local_var rq, prx, w;

  if (strlen(item) == 0)
  {
    err_print('http_send_recv3: empty item\n');
    return NULL;
  }

  rq = http_mk_req( port: port, host: host, method: method, item: item, 
                    content_type: content_type,
                    data: data, version: version, add_headers: add_headers);
  if (isnull(rq))
  {
    debug_print('http_send_recv3(port: ', port, ') : http_mk_req failed\n');
    return NULL;
  }

  w = http_send_recv_req(target: target, port: port, req: rq, 
                         username: username, password: password, 
                         fetch404: fetch404, 
                         follow_redirect: follow_redirect,
                         exit_on_fail: exit_on_fail, transport: transport,
                         only_content: only_content, no_body: no_body);

  if (isnull(w))
    debug_print('http_send_recv3(port: ', port, ', host: ', host, ', transport: ', transport, ', method: ', method, ', item: ', item, ', data=', data, ', version: ', version, ', follow_redirect: ', follow_redirect, '): http_send_recv_req failed\n');
  return w;
}

##
# init request to http server
#
# @param [port:int] port to connect to
# @param [req:array] http header content
# @param [username:string] auth username for example http auth
# @param [password:string] auth password ^
# @param [fetch404:BOOL] Return 404 pages
# @param [only_content:BOOL] This is mainly used by webmirror.nasl
# @param [no_body:BOOL] false if body is empty
# @param [follow_redirect:int] maximum number of redirects to follow
# @param [exit_on_fail:BOOL] exit if fails default false
# @param [transport:string] transport type, default ENCAPS_IP
# @return [string] request response
##
function http_send_recv_req(target, port, req, username, password, 
                            fetch404, only_content, no_body, follow_redirect, 
                            exit_on_fail, transport)
{
  local_var ka, buf, v, z;
  local_var line, w, newuri, auth, newreqline, newport, ver, req2;

  if(__ka_enabled < 0)
  {
    __ka_enabled = http_keepalive_enabled(target: target, port:port, exit_on_fail: exit_on_fail, transport: transport); #FN1_1
    if(__ka_enabled == -2)
    {
      debug_print('http_send_recv_req(port: ', port, '): http_keepalive_enabled failed\n');
      return NULL;
    }
  }

  if (isnull(req))
  {
    err_print('http_send_recv_req(port: ', port, '): missing req parameter\n');
    return NULL;
  }

  #keep basic auth alive if site already visited
  if (_basic_auth_URLs[req['$uri']])
  {
    req2 = http_add_auth_to_req( req: req, username: username, password: password); #FN1_2
    if (! isnull(req2))
    {
      req = req2;
     debug_print(level: 2, 'Opportunistic Basic authentication on URL ', req['$uri'], '\n');
    }
    req2 = NULL;
  }

  ka = __ka_enabled; 
  if (ka)
  {
    req['Connection'] = 'Keep-Alive';
  }

  v = _http_send_recv_once( target: target, port: port, req: req, ka: ka, fetch404: fetch404, only_content: only_content, no_body: no_body,  follow_redirect: follow_redirect, transport: transport, username:username, password:password, exit_on_fail: exit_on_fail);
  
  if (isnull(v))
  {
    debug_print('http_send_recv_req(port: ', port, '): _http_send_recv_once failed - method=', req['$method'], ' item=', req['$uri'], ' port=', req['$port'], ' version=', req['$version'], '\n');
    return NULL;
  }

  # ENTER HERE 1
  

  return v;
}

##
# This is a compatibility function. 
# It works like the old http_send_recv(), 
# but manages keep-alive and authentication. 
# It opens a socket to the web server, 
# sends it to the web server and reads the result. 
#
# @param [port:int] port to connect to
# @param [data:string] the message body 
# @param [username:string] auth username for example http auth
# @param [password:string] auth password ^
# @param [fetch404:BOOL] Return 404 pages
# @param [only_content:BOOL] This is mainly used by webmirror.nasl
# @param [no_body:BOOL] false if body is empty
# @param [exit_on_fail:BOOL] exit if fails default false
# @param [transport:string] transport type, default ENCAPS_IP
# @return [string] request response
##
function http_send_recv_buf(port, data, username, password, fetch404, only_content, no_body, exit_on_fail, transport)
{
  local_var ka, cnx_line, buf, v, payload_idx, headers, rq, a;

  if (isnull(data))
  {
    err_print('http_send_recv_buf(port: ', port, '): missing data parameter\n');
    return NULL;
  }

  payload_idx = stridx(data, '\r\n\r\n');
  if (payload_idx < 0)
    headers = data;
  else
  {
    headers = substr(data, 0, payload_idx + 1);
    payload_idx += 4;
  }
  cnx_line = egrep(string: headers, pattern: "^Connection *:", icase: 1);
  ka = NULL;
  if (strlen(cnx_line) > 0)
    if ("Keep-Alive" >< cnx_line) ka = 1;
    else if ("Close" >< cnx_line) ka = 0;

  if (isnull(ka))
  {
    if(__ka_enabled < 0) __ka_enabled = http_keepalive_enabled(port:port, exit_on_fail: exit_on_fail, transport: transport);
    if(__ka_enabled == -2)
    {
      debug_print('http_send_recv_buf(port: ', port, '): http_keepalive_enabled failed\n');
      return NULL;
    }
    if (__ka_enabled > 0) ka = 1; else ka =0;
  }

  if (cnx_line)
    if (ka)
      headers = strcat(headers, 'Connection: Keep-Alive\r\n');
    else
      headers = strcat(headers, 'Connection: Close\r\n');

  if (payload_idx < 0)
    buf = headers;
  else
    buf = strcat(headers, '\r\n', substr(data, payload_idx));

  v = _http_send_recv_once( port: port, buf: buf, ka: ka, fetch404: fetch404,
                            only_content: only_content, no_body: no_body, 
                            transport: transport, 
                            exit_on_fail: exit_on_fail);
  if (isnull(v))
  {
    debug_print('http_send_recv_buf(port: ', port, '): _http_send_recv_once failed\n');
    return NULL;
  }

  if (v[0] !~ '^HTTP/1\\.[01] +40[17] ') return v;

  rq = http_add_auth_to_req( req: make_array(), headers: v[1], 
                             username: username, password: password);
  if (isnull(rq))
  {
    debug_print(level: 2, 'http_send_recv_buf(port: ', port, '): http_add_auth_to_req failed\n');
    return v;
  }

  while (1)
  {
    a = egrep(string: headers, pattern: "^Authorization *:", icase: 1);
    if (strlen(a) > 0) headers -= a;
    else
    {
      a = egrep(string: headers, pattern: "^Proxy-Authorization *:", icase: 1);
      if (strlen(a) > 0)
        headers -= a;
      else
        break;
    }
  }
  if (strlen(rq["Authorization"]) > 0)
    headers = strcat(headers, 'Authorization: ', rq["Authorization"], '\r\n');  
  if (strlen(rq["Proxy-Authorization"]) > 0)
    headers = strcat(headers, 'Proxy-Authorization: ', rq["Authorization"], '\r\n');  

  if (payload_idx < 0)
    buf = headers;
  else
    buf = strcat(headers, '\r\n', substr(data, payload_idx));
  
  v = _http_send_recv_once( port: port, buf: buf, ka: ka, fetch404: fetch404, 
                            transport: transport,
                            exit_on_fail: exit_on_fail);
  if (isnull(v))
    debug_print('http_send_recv_buf(port: ', port, '): _http_send_recv_once failed\n');

  return v;
}

##
# exit keep alive global sockets 
# This function is called when libarary loads
#
# @return [NULL]
##
function on_exit()
{
  if(__ka_socket)
  {
    http_close_socket(__ka_socket);
    __ka_socket = NULL;
  }
}
# init the keep alive status when this inc 
# is added to a nasl. This will release any global
# keep alive sockets and set them to NULL
if ( 0 ) on_exit();


##
# set the global for max request size
#
# @param [_FCT_ANON_ARGS[0]:int] size of max in bytes
# @return [NULL]
##
function http_set_max_req_sz()
{
  local_var sz;
  sz = int(_FCT_ANON_ARGS[0]);
  if (sz <= 0)
  {
    err_print("http_set_max_req_sz: invalid (or missing) argument: ", sz);
    return;
  }
  _http_max_req_sz = sz;
}

##
# recv a socket http request body without
# the http header
#
# @param [socket:object] socket to recv on
# @param [headers:string] headers, if null recv header
# @param [length:int] length minus the header
# @return [NULL] on fail | [string] on success
##
function http_recv_body(target, socket, status_line, headers, length)
{
  local_var h, cl, l, min, max, x, n, to, dobrk;
  local_var incomplete_read;
    
  if (isnull(headers))
  {
    h = http_recv_headers3(target: target, socket:socket);
    if (isnull(h)) return NULL;
  }
  else
  {
    h = headers;
  }

  if (!isnull(__http_recv_body_cb))
  {
    return __http_recv_body_cb(target:target, socket:socket, status_line:status_line, headers:h, length:length);
  }

  l = -1;
  cl = eregmatch(pattern: '(^|\r\n)Content-length:[ \t]*([0-9]+)', string: h, icase: 1);
  if(! isnull(cl)) l = int(cl[2]);
  # "l" = Content-Length or -1 now
  max = -1;
  min = -1;

  if(egrep(pattern:"^transfer-encoding: *chunked", string:h, icase:TRUE))
  {
    local_var tmp, body;
    body = "";
    
    dobrk = 0;
    while(1)
    {
      tmp = recv_line(socket:socket, length:4096, timeout: __http_read_timeout);
      l = hex2dec(xvalue:tmp);
      if ( l + strlen(body) >= _http_max_req_sz )
      {
         l = _http_max_req_sz - strlen(body);
         dobrk = 1;
         debug_print('http_recv_body: read stopped after ', _http_max_req_sz / 1024, 'KB\n');
      }
      if (l > 0)
        body  = strcat(body, recv(socket:socket, length:l, min:l, timeout: __http_read_timeout));
      
      recv (socket:socket, length:2, min:2);
      if (dobrk)
        _http_close_socket_ka_only(socket);
      if (l == 0 || dobrk)
      {
        return(body); # This is expected - don't put this line before the previous
      }
    }
  }
  
  if (length) max = length;
  if (l >= 0) min = int(l);
  if (l >= max || min >= max ) max = l;
  if ( max < 0)
  {
    debug_print(level: 3, 'http_recv_body: bogus or no Content-length field, and no \'length\' parameter set! Defaulting to ', _http_max_req_sz, '\n');
    max = _http_max_req_sz;
    incomplete_read = 1;
  }
  if ( max > _http_max_req_sz ) { max = _http_max_req_sz; incomplete_read = 1; }
  if ( min > _http_max_req_sz ) { min = _http_max_req_sz; incomplete_read = 1; }
 
  debug_print(level: 3, "http_recv_body: min=", min, "; max=", max, "\n");
  if (min > 0)
  {
    x = recv(socket: socket, length: max, min: min, timeout: __http_read_timeout);
    if (strlen(x) < max) incomplete_read = 1;
  }
  else
  {
    n = recv(socket: socket, min:max, length: max, timeout: __http_read_timeout);
    x = n;
    while ( strlen(n) >= max && max != 0 )
    {
      n = recv(socket: socket, length: max, timeout: __http_read_timeout);
      x += n;
      if( strlen(x) > _http_max_req_sz)
      {
        debug_print('http_recv_body: read stopped after ', _http_max_req_sz / 1024, 'KB\n');
        incomplete_read = 1;
        break;
      }
    }
  }
  if (incomplete_read)
    _http_close_socket_ka_only(socket);
  return(x);
}

##
# recv a http response
# 
# @param [socket:object] socket to recv on
# @param [code:BOOL] if true recv till \r\n or null line
# @return [string] http response
##
function _http_recv(target, socket, code)
{
  local_var h, b, l;
  if (code)
  {
    h = strcat(code); # Convert to string, just in case
    repeat
    {
      l = recv_line(socket: socket, length: 2048, timeout: __http_read_timeout);
      h = h + l;
    }
    until (! l || l =~ '^[\r\n]+$'); # EOF or empty line
    if (!l) return h;
  }
  else
  {
    h = http_recv_headers3(target: target, socket:socket);
    if (isnull(h))
    {
      return(NULL);
    }
    else if ( ! ereg(pattern:"^HTTP/.* [0-9]*", string:h) ) return h;
    h = strcat(h, '\r\n');
  }
  b = http_recv_body(target: target, socket: socket, headers: h, length:0);
  return strcat(h, b);
}

##
# This function reads everything
# Note that body length will be ignored if the Content-length field is set
#
# @param [socket:object] socket object to recv on
# @param [code:BOOL] if true recv till \r\n or null line
# @return [list] {code, header, body}
##
function http_recv3(target, socket, code)
{
  local_var h, b, l;
  if (code)
  {
    repeat
    {
      l = recv_line(socket: socket, length: 2048, timeout: __http_read_timeout);
      h = h + l;
    }
    until (! l || l =~ '^[\r\n]+$'); # EOF or empty line
    if (!l) return h;
  }
  else
  {
    code = recv_line(socket: socket, length: 2048, timeout: __http_read_timeout);
    if (! code) return NULL;
    h = http_recv_headers3(target: target, socket: socket);
    if (isnull(h))
    {
      return make_list(code);
    }
    if (code !~ "^HTTP/.* [0-9]+ ") make_list(code, h);
  }
  b = http_recv_body(target: target, socket: socket, headers: h, length:0);
  if ( ! isnull(b) )
    return make_list(code, h, b);
  else
    return make_list(code, h);
}

##
# Test if http server is not responding
# 
# @param [port:int] port to retrieve on
# @param [retry:int] number of times to attempt
# @return [int] 1 server error|0 OK
##
function http_is_dead(target, port, retry)
{
  local_var soc, url, req, rq, code, h, h2, b, i;
  
  if (retry <= 0) retry = 1; # or 0?

  i = 0;
  i = 0;

  soc = http_open_sock_err(target:target, port: port);
  while (!soc && i++ < retry)
  {
    sleep(1); # Should we use sleep(i) ?
    soc = http_open_sock_err(target: target, port: port);
  }
  if (! soc) return 1;

  # NB: http_head does not work against SWAT & VNC (& probably others...)
  url = strcat("/", rand_str(length: 8, charset: "abcdefghijklmnopqrstuvwxyz"));
  rq = http_mk_get_req(port: port, item: url);
  if (target) rq['Host'] = target;
  req = http_mk_buffer_from_req(req: rq);
  send(socket:soc, data:req);
  for (i = 0; i <= retry; i ++)
  {
   code = recv_line(socket:soc, length: 1024, timeout: __http_read_timeout);
   if (strlen(code) > 0)
   {
     h = http_recv_headers3(target: target, socket:soc);
     # MA 2009-07-23: if we cannot read the headers, the server is not dead as 
     # it answered with a code
     if (! isnull(h))
     {
       h2 = strcat(code, h);
       b = http_recv_body(target: target, socket: soc, headers: h2);
     }
     break;
   }
   else
     sleep(1);
  }
  http_close_socket(soc);
  if (!code) return (1);
  # 500: internal server error
  # 501: not implemented = unsupported method...
  # 502: Bad gateway = upstream server sends an invalid response
  # 503: service unavailable = temporary overloading...
  # 504: gateway timeout = no timely response from upstream server
  if (ereg(pattern: "^HTTP/1\.[01] +50[234]", string: code)) return(1);
  return (0);
}

##
# get the timeout set for http sockets
#
# @return [string] timeout in seconds 
##
function http_get_read_timeout()
{
  if (isnull(__http_read_timeout))
    return get_read_timeout();
  else
    return __http_read_timeout;
}

##
# set the timeout on a recv call
# 
# @param [_FCT_ANON_ARGS[0]:int] timeout in seconds
# @return [int] 
##
function http_set_read_timeout()
{
  local_var to;
  local_var old;

  to = _FCT_ANON_ARGS[0];
  old = __http_read_timeout;
  if (isnull(to))
  {
    __http_read_timeout = NULL;
  }
  else if (to <= 0)
  {
    err_print('http_set_read_timeout: invalid timeout ', to, ' - ignored');
  }
  else
  {
    __http_read_timeout = to;
  }
  return old;
}

##
# retreive the most recent sent
# 
# @return [string] previouse request string
## 
function http_last_sent_request()
{
  return __http_sent_request;
}

##
# set if http will redirect get
# 
# @param [_FCT_ANON_ARGS[0]:BOOL] sets __redirect_with_get
# @return [BOOL] the old __redirect_with_get value
##
function http_redirect_with_get()
{
  local_var old;

  old = __redirect_with_get;
  __redirect_with_get = _FCT_ANON_ARGS[0];
  return old;
}

##
# set the global http_incr_timeout_on_err
# 
# @param [_FCT_ANON_ARGS[0]:int] value to set to http_incr_timeout_on_err
# @return [int] old value
##
function http_incr_timeout_on_err()
{
  local_var old;

  old = __http_incr_timeout_on_err;
  __http_incr_timeout_on_err = _FCT_ANON_ARGS[0];
  return old;
}

##
# set the global __http_use_async_sock
#
# @param [_FCT_ANON_ARGS[0]:int] value to set __http_use_async_sock
# @return [int] the old value
##
function http_set_async_sock()
{
  local_var old;
  old = __http_use_async_sock;
  __http_use_async_sock = int(_FCT_ANON_ARGS[0]);
  return old;
}


##
# set the callback for http_recv_body()
#
# @return NULL is error, 0 on success
##
function http_set_recv_body_callback(callback)
{
  if (isnull(callback)) return NULL;

  __http_recv_body_cb = callback;

  return 0;
}

##
# get a callback (function pointer)
#
# @return function pointer to the body recv callback
##
function http_get_recv_body_callback()
{
  return __http_recv_body_cb;
}

##
# check if header is in a http request array 'req'
#
# @param [req:array] http request
# @param [header:string] header to check
# @return TRUE if header is set | FALSE if not set
#
##
function _http_chk_header(req, header)
{
  local_var k;

  foreach k (keys(req))
    if (ereg(string:k, pattern:'^' + header + '$', icase:TRUE))
      return TRUE;

  return FALSE;
}
