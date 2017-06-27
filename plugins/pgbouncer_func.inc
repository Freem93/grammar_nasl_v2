# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@

# pgbouncer_func.inc
# $Revision: 1.1 $

include ("stream_func.inc");

# Send a startup message.                                             
#                                                                     
# nb: see <http://developer.postgresql.org/pgdocs/postgres/protocol-message-formats.html>.
function pgbouncer_login(port, user, database)
{
  local_var soc = open_sock_tcp(port);
  if (!soc) return NULL;

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  local_var req = mkword(0x03) + mkword(0x00) +    # protocol version (3.0)
    "user" + mkbyte(0) + user + mkbyte(0) +
    "database" + mkbyte(0) + database + mkbyte(0) +
    "client_encoding" + mkbyte(0) + "UTF8" + mkbyte(0) +
    mkbyte(0);
  req = mkdword(strlen(req) + 4) + req;
  send(socket:soc, data:req);
  local_var res = recv(socket:soc, length:2048, min:1);
  close(soc);
  return res;
}

# parse version from response
# or return as unknown version
function parse_remote_version(res)
{
  local_var version = NULL;
  # see if version was returned
  local_var server_ver = strstr(res, "server_version");
  if (!isnull(server_ver))
  {
    # e.g. server_version.1.6/bouncer
    local_var pat = "^server_version\x00+([0-9]+(?:\.[0-9]+)*)/bouncer";
    local_var match = pregmatch(pattern:pat, string:server_ver);
    if (!isnull(match) && len(match) == 2)
    {
      version = match[1];
    }
  }
  return version;
}
