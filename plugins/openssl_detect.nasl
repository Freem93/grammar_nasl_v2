#TRUSTED 01101feeffca5bb2dc4758185f7c83b673f4dce0bc29b1eb36dde5989d77530184077ea610122de87ca3c8966fd1dee9cbc1df5e323a2fb533a01f8332df3d139bec9376d58e1ce48cb12117de942ae6fda75f1f27c8adf887f9bc68e45a1af5c8f389f4db1d1d2a116d663b4ed56b0e32958c87a7345a083657a86d6eab66fc8acb0b8bf40346df258987d7d446fcf879f806e16018ed9bfeafe143ebf90d311e7a690c1570ffb54df35376a69f9a386a8067a1ba951445c20efed295f3fe44f75300e575278f29aefa693417fe8e5cd4eaee6771d765c1391f759543f6ed971fe8f87835f1f9e114c50e8c940accb67bd5becb67146995f4b4aa5d7333fd0c3edac2b74202126b557c6486f463c72580dd70c5f09d9edc9215baf291c3f8628f59de4c8bc01a957688b776fdaab4b9ae9fd5f44ab29d89bb85321e20a9a7a4ff35365b3b37cfcc4ab872e61da797e6c2205846a7173b2f36de016b47f9541d6a98d37c5fec7d2fa2d21fdceeaf9615e379b473e993a8d4e1e02fa6890a4ff49395e3280ca06762872b437dfd5c803ad3d89e03a10451b1e9ebdcfc3ce24b548c2bef58c2f88db7c293c8a0759394c16175d16bd79bc77a8fd7aabbb902c1ddc8189d00e3c6686adf4f2c491cd508740e7c2b2277c1edfd3594e21564c81bf65eae350fee6099dcdfe5cbe56d3f968f3af67c7273e0bbc4e13083be2537b8a4
#
# (C) Tenable Network Security, Inc.
#


if ( !defined_func("socket_get_error") ) exit(0);

include("compat.inc");

if (description)
{
 script_id(50845);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2013/10/18");

 script_name(english:"OpenSSL Detection");
 script_summary(english:"OpenSSL detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote service appears to use OpenSSL to encrypt traffic.");

 script_set_attribute(attribute:"description", value:
"Based on its response to a TLS request with a specially crafted
server name extension, it seems that the remote service is using the
OpenSSL library to encrypt traffic.

Note that this plugin can only detect OpenSSL implementations that
have enabled support for TLS extensions (RFC 4366).");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"see_also", value:"http://www.openssl.org");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencies("ssl_supported_versions.nasl");
 script_require_keys("SSL/Supported");
 exit(0);
}

include("acap_func.inc");
include("byte_func.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("imap_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("misc_func.inc");
include("nntp_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");
include("ssl_funcs.inc");
include("telnet2_func.inc");
include("xmpp_func.inc");

##
# Formats a server name entry
#
# @param name server name
# @param type server name type
# @return formatted server name
#
##
function server_name(name, type)
{
  return mkbyte(type) + mkword(strlen(name)) + name;
}

##
# Creates a server name extension
#
# @anonparam hostname1, hostname2, ..., hostnamen
# @return formatted server name TLS extension
#
##
function server_name_ext()
{
  local_var host,srvname,srvname_list;

  foreach host (_FCT_ANON_ARGS)
  {
    srvname = server_name(name: host, type:0);
    srvname_list += srvname;
  }

  return    mkword(0) +                         # extension type
            mkword(strlen(srvname_list) + 2) +  # extension length
            mkword(strlen(srvname_list)) +      # length of server name list
            srvname_list;                       # server name list
}

##
# Send ClientHello with server name extension and wait for response
#
# @param soc socket to the ClientHello to
# @param hostname hostname used to generate a TLS server name extension
# @return server response
#
##
function client_hello_sendrecv(soc,hostname)
{
  local_var chello, exts, exts_len, rec, recs,  version;

  version   = raw_string(0x03, 0x01);

  exts = server_name_ext(hostname);
  # length of all extensions
  exts_len  = mkword(strlen(exts));
  chello = client_hello(v2hello:FALSE, version:version,extensions:exts,extensionslen:exts_len);

  send(socket:soc, data: chello);

  # Receive target's response.
  recs = NULL;
  repeat
  {
    rec = recv_ssl(socket:soc);
    if (isnull(rec)) break;
    recs += rec;
  } until (!socket_pending(soc));

  return recs;
}

##
# OpenSSL detection based on response to TLS request with certain TLS server name extensions
#
# @param port SSL port to test
# @param good valid hostname for TLS  server name extension
# @param long hostname with more than 255 bytes
# @param zero hostname with all zero bytes
# @return
#       -  1  test succeeded
#       -  0  test failed
#       -  exit if socket cannot be created on the port
# @remark
# OpenSSL 0.9.8o source code says about servername extension:
#  - Only the hostname type is supported with a maximum length of 255.
#  - The servername is rejected if too long or if it contains zeros,
#    in which case an fatal alert is generated.
#
# RFC 4366 implies that the servername length can be up to 2^16 -1
#
# Starting version 0.9.8f (Release date: Oct 2007), OpenSSL supports TLS extensions,
# but it's disabled by default.
#
# Starting version 0.9.8j (Release date: Jan 2009), the TLS extensions support
# is enabled by default.
#
##
function openssl_tlsext_hostname_test(port, good, long, zero)
{
  local_var soc,soc_err,res, ret;

  # test 1,  valid hostname for openssl tls server name extension
  # expected ret: server hello
  soc = open_sock_ssl(port);
  if ( ! soc ) exit(1,"Failed to open a socket on port "+port+".");
  res = client_hello_sendrecv(soc:soc,hostname:good);
  close(soc);
  if(isnull(res)) return 0;

  # Look for ServerHello
  ret = ssl_find(
    blob:res,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if(isnull(ret)) return 0;



  # test 2, hostname with more than 255 bytes
  # expected ret for OpenSSL: no response
  #                           the source code says the server should return a fatal alert
  #                           but in several test cases, it responded with a TCP FIN.
  #                           In other test cases, it returns a fatal alert.
  #
  #
  # expected ret for MS TLS implementation (schannel.dll): server hello
  # expected ret for OpenSSL that doesn't support TLS extensions: server hello
  soc = open_sock_ssl(port);
  if ( ! soc ) exit(1, "Failed to open a socket on port "+port+".");
  res = client_hello_sendrecv(soc:soc,hostname:long);
  soc_err = socket_get_error(soc);
  close(soc);

  # Look for unrecognized_name fatal alert
  if(! isnull(res))
  {
    ret = ssl_find(
      blob:res,
      "content_type", SSL3_CONTENT_TYPE_ALERT
    );
    if(isnull(ret) || !(ret['level'] == 2 && ret['description'] == 112)) return 0;
  }
  # Look for TCP FIN/RST
  else
  {
    if(soc_err != ECONNRESET) return 0;
  }

  # test 3, hostname with all zero bytes
  soc = open_sock_ssl(port);
  if ( ! soc ) exit(1, "Failed to open a socket on port "+port+".");
  res = client_hello_sendrecv(soc:soc,hostname:zero);
  soc_err = socket_get_error(soc);
  close(soc);

  # Look for unrecognized_name fatal alert
  if(! isnull(res))
  {
    ret = ssl_find(
      blob:res,
      "content_type", SSL3_CONTENT_TYPE_ALERT
    );
    if(isnull(ret) || !(ret['level'] == 2 && ret['description'] == 112)) return 0;
  }
  # Look for TCP FIN/RST
  else
  {
    if(soc_err != ECONNRESET) return 0;
  }


  # do test1 again to double check
  # expected ret: server hello
  soc = open_sock_ssl(port);
  if ( ! soc ) exit(1,"Failed to open a socket on port "+ port+"." );
  res = client_hello_sendrecv(soc:soc,hostname:good);
  close(soc);
  if(isnull(res)) return 0;
  ret = ssl_find(
    blob:res,
    "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
    "handshake_type", SSL3_HANDSHAKE_TYPE_SERVER_HELLO
  );
  if(isnull(ret)) return 0;

  # all tests passed
  return 1;

}


get_kb_item_or_exit("SSL/Supported");

port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Check for TLS; extensions only available in TLSv1 and later
tls10 = tls11 = tls12 = 0;

list = get_kb_list('SSL/Transport/'+port);
if(! isnull(list))
{
  list = make_list(list);
  foreach encap (list)
  {
    if      (encap == ENCAPS_TLSv1)         tls10 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv11) tls11 = 1;
    else if (encap == COMPAT_ENCAPS_TLSv12) tls12 = 1;
  }
}

if(! (tls10 || tls11 || tls12))
  exit(0, 'The SSL-based service listening on port '+port+' does not appear to support TLSv1 or above.');

# good hostname
good  = 'localhost.localdomain';
# hostname with more than 255 bytes in TLS extension is invalid for OpenSSL
long  = crap(data:good, length:256);
# hostname with all zero bytes in TLS extension is invalid for OpenSSL
zero  = crap(data:raw_string(0x0) ,length:10);

ret = openssl_tlsext_hostname_test(port:port, good:good, long: long, zero: zero);
if(ret == 1)
{
  security_note(port:port);
  set_kb_item(name:"OpenSSL_port", value:port);
}
