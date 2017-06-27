#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40947);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2009-3231");
  script_bugtraq_id(36314);
  script_osvdb_id(57917);
  script_xref(name:"Secunia", value:"36660");

  script_name(english:"PostgreSQL LDAP Anonymous Bind Authentication Bypass");
  script_summary(english:"Tries to login using a blank password");

  script_set_attribute(attribute:"synopsis", value:
"The database service running on the remote host has an authentication
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL running on the remote host has an
authentication bypass vulnerability. If PostgreSQL is using LDAP
authentication, and the LDAP server is configured to allow anonymous
binds, it may be possible to log into the PostgreSQL server using a
blank password. A remote attacker could exploit this to gain access to
the database server, possibly as an administrator.

There are reportedly other vulnerabilities in this version of
PostgreSQL, though Nessus has not checked for those issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news.1135");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/support/security");
  script_set_attribute(attribute:"solution", value:"Upgrade to PostgreSQL 8.2.14 / 8.3.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("postgresql_detect.nasl");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


function login(port, user, pass)
{
  local_var soc, req, reqlen, data, reslen, res;

  set_byte_order(BYTE_ORDER_BIG_ENDIAN);
  soc = open_sock_tcp(port);
  if (!soc) exit(1, "Unable to create a socket.");

  # Send the initial login request
  req = string(
    mkword(0x03), mkword(0x00),
    "user", mkbyte(0),
      user, mkbyte(0),
    "database", mkbyte(0),
      unixtime(), mkbyte(0),
    "client_encoding", mkbyte(0),
      "UNICODE", mkbyte(0),
    "DateStyle", mkbyte(0),
      "ISO", mkbyte(0),
    mkbyte(0)
  );
  reqlen = strlen(req);
  data = mkdword(reqlen + 4) + req;
  send(socket:soc, data:data);
  res = recv(socket:soc, length:1, min:1);
  if (isnull(res)) exit(1, "The server failed to respond.");
  if (res[0] != "R") exit(1, "Unexpected response error (" + res[0] + ").");

  res += recv(socket:soc, length:4, min:4);
  if (strlen(res) < 5) exit(1, "Unable to get the length of the response.");

  reslen = getdword(blob:res, pos:1);
  if (reslen > 2048) exit(1, "Unexpected big response.");

  res += recv(socket:soc, length:reslen - 4);
  if (strlen(res) == 5) exit(1, "The server failed to respond.");

  # And send the password
  req = string(mkbyte(0x70), mkdword(strlen(pass) + 5), pass, mkbyte(0));
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  if (isnull(res)) exit(1, "The server failed to respond.");
  close(soc);

  return res;
}


#
# Execution begins here
#

port = get_kb_item("Services/postgresql");
if (!port) port = 5432;
if (!get_tcp_port_state(port)) exit(1, "The port is not open.");

# If the system is vulnerable, auth will succeed for any username
user = SCRIPT_NAME;
pass = '';
auth_res = login(port:port, user:user, pass:pass);

# The first 9 bytes will tell us whether or not authentication succeeded
if (auth_res >= 9)
{
  resp_type = auth_res[0];
  resp_len = getdword(blob:auth_res, pos:1);
  auth_type = getdword(blob:auth_res, pos:5);

  if (resp_type == 'R' && resp_len == 8 && auth_type == 0)
    security_warning(port);
  else
    exit(0, "The host is not affected.");
}
else exit(1, "Unexpectedly short response received.");
