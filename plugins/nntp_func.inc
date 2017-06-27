#TRUSTED 0ce21bbb013e6afa58d52c64b959093985f5510d0112500f917345d817b318ef70e9b0ef258f3454885b7b3cef2b953d827d86d36ba8339e29a06087be1b09250421f3d0c253889ceb8acb108e6ff8a611b10cabd0bc3529bd794b4ac382fd6872afdb52c1085200c58b8d324d4e305a9203b30221ccdac2d3e7deb0729882a1c35403d73b4b7b8320d226cc325f0d8ae8680b7839bce3f7005dfa52d04264568f86a566d7bbc70a44ed6abe53c396a845830ab0705456b1174bdc4e908180287214bb972b88d2d4d847282675d7d688f1658c1603a22439eee362a5ec511d8e36c3d5393eb7caea66082ab2f3dff6d868e4a0da56edbe4e7b520210db00b26cca6cba61f39a699b0d08c83db9b0c29456ae7c7320aab0e5ab6d75e89abe57012c50a59fd15594b76d30d2687c3cdd50ceda566fb8a41aa6a717cd651300ea0dbb437262f00361bfc62da4be338e36b57c9fcb54a43b4520bfa70b26f20806fa6a0b01504aecbb07260eca47ce21dc4385cf8fed44b44b6b9e0643277fb5094e8d5d289db7142058d63e6fadc7dc78ac82f7c36fa01318d8164c2484e810f08538559ae2a46e3eda23d2010099200d048d7e1c8c2d8027f0f50bf521c72368a7dbc5a35e17c48563eb40632c4a73772706ad8e91e86b65de0989f7ac1b0ba286a7de26143ebfbd53ca6e81574408681434e9246cff5d81dc10a38b193a6eafc9
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# nntp_func.inc
# Revision: 1.9
#

#
# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.
#

function nntp_auth(socket, username, password)
{
 local_var	 buff;
 if (!username) return (0);

 send(socket:socket, data: string("AUTHINFO USER ", username, "\r\n"));
 buff = recv_line(socket:socket, length:2048);
 send(socket:socket, data: string("AUTHINFO PASS ", password, "\r\n"));
 buff = recv_line(socket:socket, length:2048);
 if ("502 " >< buff) { 
  debug_print(string("Bad username/password for NNTP server"));
  return (0);
 }
 return (1);
}

function nntp_connect(port, username, password)
{
  local_var buff, s, a;
  s = open_sock_tcp(port);
  if (s) { 
   buff = recv_line(socket: s, length: 2048);
   a = nntp_auth(socket: s, username: username, password: password); 
   if (! a) { close(s); return NULL; }
  }
  return (s);
}

function nntp_post(socket, message)
{
  local_var	buff;

  if (! socket) { return (0); }
  send(socket: socket, data:string("POST\r\n"));
  buff = recv_line(socket:socket, length: 2048);

  # 340 = Go ahead; 440 = posting prohibited
  if ("340 " >< buff) {
    send(socket: socket, data: message);
    buff = recv_line(socket: socket, length: 2048);
    if ("240 " >< buff) { return (1); }
    if (ereg(pattern: "^4[34][0-9] +.*unwanted distribution .*local", 
             string: buff, icase:1) &&
        ereg(pattern: "Distribution: +local", string: message)) {
	return -1;
    }
  }
 return (0);
}

function nntp_article(id, timeout, port, username, password)
{
  local_var	buff, s, t;
  for (t=0; t < timeout; t=t+5)
  {
    sleep(5);
    s = nntp_connect(port:port, username: username, password: password);
    if (s) {
      send(socket:s, data: string("ARTICLE ", id, "\r\n"));
      buff = recv_line(socket: s, length: 2048);
      send(socket:s, data: string("QUIT\r\n"));
      close(s);
      # display(string("Article > ", buff));
      # WARNING! If the header X-Nessus is removed, change this line!
      if (ereg(pattern:"^220 .*X-Nessus:", string: buff)) { return (buff); }
    }
  }
  return (0);
}

function nntp_make_id(str)
{
 local_var	id;
 # RFC 822 says that should use a full domain name. Some new servers 
 # check that the domain part is valid so we use "nessus.org"
 # We do not check "str", but it should not contain '@' or '>'
 id=string("<", str, ".x", rand(), "@nessus.org>");
 return(id);
}

##
# Sends an NNTP request.
#
# @param data   The NNTP request
# @param socket The NNTP socket
##
function nntp_send(data, socket)
{
  # Sanity check parameters.
  if (isnull(data))
    return NULL;

  if (!socket)
    return NULL;

  send(socket:socket, data:data);
}

##
# Receives an NNTP response.
#
# @param code         The response code we are expecting
# @param exit_on_fail Boolean indicating failure action, defaults to
#                     FALSE
# @param socket       The NNTP socket
#
# @return A array containing the NNTP response.
##
function nntp_recv(code, exit_on_fail, socket)
{
  local_var line, port, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Set defaults.
  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  # Get the port the socket is connected to for audit messages.
  if (defined_func("get_peer_name"))
  {
    port = get_peer_name(socket);
    port = port[1];
  }
  else port = NULL;

  # Get the response status.
  line = recv_line(socket:socket, length:1024);
  if (isnull(line))
  {
    if (exit_on_fail)
    {
      if (isnull(port)) exit(1, "The NNTP server didn't respond.");
      else exit(1, "The NNTP server listening on port " + port + " didn't respond.");
    }
    return NULL;
  }

  # Create the response object.
  res = make_array(
    "code", int(substr(line, 0, 2)),
    "body", line,
    "status", line
  );

  # Ensure we got the expected response.
  if (!isnull(code) && res["code"] != code && exit_on_fail)
  {
    if (isnull(port)) exit(1, "The NNTP server returned an unexpected response: " + res["status"]);
    else exit(1, "The NNTP server listening on port " + port + " returned an unexpected response: " + res["status"]);
  }

  # If the status code doesn't indicate a multi-line data block, don't
  # look for more data.
  if (string(res["code"]) !~ "^(10[01]|2(1[15]|2[01245]|3[01]|81))$")
    return res;

  # Get the response body.
  while (TRUE)
  {
    line = recv_line(socket:socket, length:1024);
    if (isnull(line))
      return NULL;

    # Check for end of multi-line data block.
    if (line == '.\r\n')
    {
      res["body"] += line;
      break;
    }

    # Un-stuff lines that begin with a period.
    if (line =~ "^\.")
      line -= ".";

    res["body"] += line;
  }

  return res;
}

##
# Sends an NNTP command and receives the response.
#
# @param code         The response code we are expecting
# @param cmd          The command to send
# @param exit_on_fail Boolean indicating failure action, defaults to
#                     FALSE
# @param socket       The NNTP socket
#
# @return A array containing the NNTP response.
##
function nntp_cmd(cmd, code, exit_on_fail, socket)
{
  local_var port, res;

  # Sanity check parameters.
  if (isnull(cmd))
    return NULL;

  if (!socket)
    return NULL;

  # Get the port the socket is connected to for audit messages.
  if (defined_func("get_peer_name"))
  {
    port = get_peer_name(socket);
    port = port[1];
  }
  else port = NULL;

  # Send a request to the NNTP server.
  nntp_send(socket:socket, data:cmd + '\r\n');

  # Receive a response from the NNTP server.
  res = nntp_recv(socket:socket);

  # Ensure that we got a response.
  if (isnull(res))
  {
    if (exit_on_fail)
    {
      if (isnull(port)) exit(1, "The NNTP server didn't respond to our '" + cmd + "' command.");
      else exit(1, "The NNTP server listening on port " + port + " didn't respond to our '" + cmd + "' command.");
    }
    return NULL;
  }

  # Ensure we got the expected response.
  if (!isnull(code) && res["code"] != code && exit_on_fail)
  {
    if (isnull(port)) exit(1, "The NNTP server returned an unexpected response: " + res["status"]);
    else exit(1, "The NNTP server listening on port " + port + " returned an unexpected response: " + res["status"]);
  }

  return res;
}

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The NNTP socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return An NNTP connection in StartTLS mode.
##
function nntp_starttls(encaps, socket)
{
  local_var res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Send command to request StartTLS negotiation.
  res = nntp_cmd(socket:socket, cmd:'STARTTLS\r\n');
  if (res["code"] != 382)
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl")) return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}
