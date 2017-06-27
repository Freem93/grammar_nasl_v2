#TRUSTED 22a3c35ebfbb72138ef67880a967e7aebcd48dd2ecde1ec1ec87cea1b5abb97429bed9566b03a792efa0b30c46b1f0a2d6ed992108c6a1b651e906cc72a6ad23a0267b62fe9277df29e2a9d13a8225ae65e5fa11d3e89b4a9287b952cd0f7ff4f7b0781d35198842a92a88958c6d8aaa79cda9a19c364041932095734a5f8f2a0f0313a3af1294732a1f3302101ae87e1ab4508ca04c959e2bf8eef89cb14f78d7864919af07d499f1acee02e4cb9e62aeb31aff275d36a9bab9de7486b213e434fe3203547ac6da0e4449f51cd8cc7f72533553886fbe804a94076cab480896577f49f5ce9b86782dbf09421f29868ac2658a5438511b42e7e73775ee16458e5a1eb78c8821e53e990d54cd4153efe9a44e747f9872782e049390b0ec13f9bd03f0f33e842762b6d163acba238a18aaece7352427b98ebc69e090f408e6fc49e7b76836683da49902c5413efb372f885b7e61ccb654903f4e31c80e933d2e2b3343f43765200898b8d97a1d5f522b0fe5cc40a8b7f2e244d9e38b785db6cb603a30ddb9198c5b3466ed1691377e016d0e296970baae0cd0288d33295ec7c0db70beb5ff6df2ed78958d37b642807171013bc86714e351fbd594adf3025e3f68202111b57d92d0a1f084ccdd664f9dc07641ce15aa304fa8a54ef75d938ce11d2ac01a9d83db5f6e101bca88d261f142b16bb354424b73933e0d1eb7450354e3
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# xmpp_func.inc
# Revision: 1.5
#

function xmpp_open(mode, port, socket)
{
  local_var req, res, to;

  if (mode != "client" && mode != "server")
    return NULL;

  if (!socket)
  {
    if (isnull(port))
      return NULL;

    socket = open_sock_tcp(port);
    if (!socket)
      return NULL;
  }

  if (mode == "client")
    to = get_host_name();
  else
    to = "example.com";

  req = 
    '<?xml version="1.0"?>' +
    "<stream:stream " +
    "xmlns='jabber:" + mode + "' " +
    "xmlns:stream='http://etherx.jabber.org/streams' " +
    "to='" + to + "' " +
    "version='1.0'>" + '\n';

  # nb: this doesn't check for an older format as described
  #     in <http://xmpp.org/extensions/xep-0035.html>, which
  #     was retracted in November 2003.
  send(socket:socket, data:req);
  res = recv_line(socket:socket, length:1024);

  if (
    !strlen(res) ||
    "jabber:" + mode >!< res ||
    "xmlns:stream=" >!< res ||
    "from=" >!< res
  )
  {
    close(socket);
    return NULL;
  }

  if (!isnull(port))
    replace_kb_item(name:"xmpp/" + port + "/banner", value:res);

  return socket;
}

#----------------------------------------------------------------#
# Function    : xmpp_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
#               'dont_read_banner' => read the initial service   #
#                 banner unless set to TRUE. (optional)          #
#               'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (xmpp_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function xmpp_starttls(socket, dont_read_banner, encaps)
{
  local_var req, res;

  if (!socket)
    return NULL;

  if (!dont_read_banner)
  {
    socket = xmpp_open(socket:socket, mode:"client");
    if (!socket)
      return NULL;
  }

  req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n";
  send(socket:socket, data:req);

  res = recv_line(socket:socket, length:1024);
  if (
    !strlen(res) ||
    "<proceed " >!< res ||
    "xml:ns:xmpp-tls" >!< res
  )
  {
    return NULL;
  }

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }

  return socket;
}
