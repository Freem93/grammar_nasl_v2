#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32316);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-1880");
  script_bugtraq_id(29123);
  script_osvdb_id(44976);
  script_xref(name:"GLSA", value:"200805-06");
  script_xref(name:"Secunia", value:"30162");

  script_name(english:"Firebird on Gentoo Linux /etc/conf.d/firebird Invocation ISC_PASSWORD Authentication Bypass");
  script_summary(english:"Tries to authenticate as SYSDBA with an empty password");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server allows remote connections to its
administrative account without a password." );
 script_set_attribute(attribute:"description", value:
"The version of Firebird on the remote host sets the 'ISC_PASSWORD'
environment variable before starting the database server and uses that
for remote client connections when a password is not supplied.  An
attacker can leverage this issue to connect as 'SYSDBA' with an empty
password and gain access to any database on the affected host except
for 'security2.fdb', which holds the database user credentials." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.gentoo.org/show_bug.cgi?id=216158" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491871/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"If running under Gentoo, use emerge to upgrade to
dev-db/firebird-2.0.3.12981.0-r6 or later. 

Otherwise, ensure that the environment variables 'ISC_USER' and
'ISC_PASSWORD' are not set when starting the service." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(255);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/14");
 script_cvs_date("$Date: 2013/01/05 03:02:42 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:firebirdsql:firebird");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("firebird_detect.nasl");
  script_require_ports("Services/gds_db", 3050);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");


port = get_kb_item("Services/gds_db");
if (!port) port = 3050;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Variable definitions.
db_user = "SYSDBA";

me = SCRIPT_NAME;
path = "/";
user = "nessus";


# Send a connection request.
req = mkdword(1) +
  mkdword(0x13) +
  mkdword(0x02) +
  mkdword(0x24) +
  mkdword(strlen(path)) +
    path +
    crap(data:raw_string(0), length:((4-(strlen(path)%4)))*(strlen(path)%4>0)) +
  mkdword(2) +
  mkdword(strlen(user+me)+6) +
  mkbyte(0x01) +
    mkbyte(strlen(user)) + 
    user +
  mkbyte(0x04) +
    mkbyte(strlen(me)) + 
    me +
  mkbyte(6) + mkbyte(0) +
    crap(data:raw_string(0), length:((4-((6+strlen(me+user))%4)))*((6+strlen(me+user))%4>0)) +
  mkdword(8) +
    mkdword(1) +
    mkdword(2) +
    mkdword(3) +
    mkdword(2) +
    mkdword(0x0a) +
    mkdword(1) +
    mkdword(2) +
    mkdword(3) +
    mkdword(4);
send(socket:soc, data:req);
res = recv(socket:soc, length:16);


# If the response contains an accept opcode...
if (strlen(res) == 16 && getdword(blob:res, pos:0) == 3)
{
  # nb: there's no password info here.
  dpb = 
    mkbyte(1) +
    mkbyte(0x1c) +
    mkbyte(strlen(db_user)) +
      db_user;

  # Try to create the database.
  #
  # nb: '/' isn't a valid name and so the database isn't actually created.
  req = mkdword(0x14) +
    mkdword(0) +
    mkdword(strlen(path)) +
      path +
      crap(data:raw_string(0), length:((4-(strlen(path)%4)))*(strlen(path)%4>0)) +
    mkdword(strlen(dpb)) + dpb;
  req += crap(data:raw_string(0), length:((4-(strlen(req)%4)))*(strlen(req)%4>0));
  send(socket:soc, data:req);
  res = recv(socket:soc, length:64);

  # There's a problem if we get a response with an error involving CreateFile.
  if (
    strlen(res) >= 16 &&
    getdword(blob:res, pos:0) == 9 &&
    (
      "CreateFile (" >< res ||
      "open O_CREAT" >< res
    )
  ) 
  {
    security_hole(port);
  }
}
close(soc);
