# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# sip.inc
#
# $Revision: 1.2 $
#

include("udp.inc");

##
# Create a connection to a SIP server.
#
# @param port The port on the remote host to connect to, 5060 by
#             default.
#
# @return A UDP socket appropriate for SIP.
##
function sip_open(port, proto)
{
  local_var soc;

  # Set defaults.
  if (isnull(port))
    port = 5060;
  if (isnull(proto))
    proto = "udp";

  if(proto == 'udp')
  {
    if (!get_udp_port_state(port)) return NULL;
    if (islocalhost()) soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:5060, dport:port);
  }
  else
  {
    if (!get_tcp_port_state(port)) return NULL;
    soc = open_sock_tcp(port);
  }
 
  return soc;
}

##
# Receives a SIP response.
#
# @param socket The SIP socket, opened by [sip_open]
#
# @return An array containing the parsed response.
##
function sip_recv(socket)
{
  local_var data, len, line, matches, res;

  # Sanity check parameters.
  if (isnull(socket))
    return NULL;

  res = make_array();

  # Clear the UDP receive buffer.
  udp_recv_line_reset();

  # Get the response status.
  line = udp_recv_line(socket:socket, length:1024);
  if (isnull(line))
    return NULL;

  res["status"] = chomp(line);

  # Get the response headers.
  while (TRUE)
  {
    line = udp_recv_line(socket:socket, length:1024);
    if (isnull(line))
      return NULL;

    line = chomp(line);
    if (line == "")
      break;

    matches = eregmatch(string:line, pattern:"^([^:]+): *(.*) *$");
    if (isnull(matches))
      return NULL;

    res["headers"][matches[1]] = matches[2];
  }

  # Get the response body.
  len = res["headers"]["Content-Length"];
  if (isnull(len))
  {
    len = int(len);
    data = recv(socket:socket, length:len, min:len);
    if (isnull(line))
      return NULL;

    res["body"] = data;
  }

  return res;
}

##
# Sends a SIP request.
#
# @param data   The SIP request
# @param socket The SIP socket, opened by [sip_open]
##
function sip_send(data, socket)
{
  # Sanity check parameters.
  if (isnull(data))
    return NULL;

  if (isnull(socket))
    return NULL;

  send(socket:socket, data:data);
}
