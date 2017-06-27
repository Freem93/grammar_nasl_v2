#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25492);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-3181");
  script_bugtraq_id(24436);
  script_osvdb_id(37231);

  script_name(english:"Firebird DataBase Server fbserver.exe p_cnct_count Value Remote Overflow");
  script_summary(english:"Detects if the Firebird database server is vulnerable to a stack overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server allows execution of arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The version of Firebird installed on the remote host is vulnerable to
a buffer overflow in its protocol handling routine.  By sending a
specially crafted 'op_connect' request, a remote, unauthenticated
attacker can execute code on the affected host with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-07-11" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cb912c4" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firebird 2.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/11");
 script_cvs_date("$Date: 2012/10/01 18:39:48 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:firebirdsql:firebird");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");

  script_dependencies("firebird_detect.nasl");
  script_require_ports("Services/gds_db");

  exit(0);
}


include("byte_func.inc");


port = get_kb_item("Services/gds_db");
if (isnull(port))
  exit(0);


if (!get_tcp_port_state(port))
  exit(0);


soc = open_sock_tcp(port);
if (!soc)
  exit(0);


# Send a connection request.
path = string("/opt/firebird/", SCRIPT_NAME, ".gdb");
if (strlen(path) % 4 == 0) pad1 = "";
else pad1 = crap(data:raw_string(0x00), length:(4-(strlen(path)%4)));
me = this_host_name();
user = "nessus";
if ((strlen(me+user)+2) % 4 == 0) pad2 = "";
else pad2 = crap(data:raw_string(0x00), length:(4-((strlen(me+user)+2) % 4)));


req = 
  mkdword(1) +                          # p_operation (1 => connect)
  mkdword(0x13) +                       # p_cnct_operation
  mkdword(0x02) +                       # p_cnct_version
  mkdword(0x24) +                       # p_cnct_client
  mkdword(strlen(path)) + path + pad1 + # p_cnct_file
  mkdword(13) +                         # p_cnct_count (number of supported protocols)

  mkdword(strlen(user+me)+6) +          # p_cnct_user_id
  mkbyte(0x01) +                        # user
  mkbyte(strlen(user)) + user +         # user running isql
  mkbyte(0x04) +                        # hostname
  mkbyte(strlen(me)) + me +             # my hostname
  mkbyte(6) + mkbyte(0) +               # password(?)
  pad2 +                                # padding 

  crap(data:'A', length:4*5*12) +       # 12 unsupported protocol
  mkdword(8) +                          # protocol 13 (valid)
  mkdword(1) +
  mkdword(2) +
  mkdword(3) +
  mkdword(2) ;

send(socket:soc, data:req);
res = recv(socket:soc, length:2048);
close(soc);


# A patched version reject the valid protocol (protocol 13)

if (
  # response is 16 chars long and...
  strlen(res) == 16 &&
  # has an 'accept' opcode and...
  getdword(blob:res, pos:0) == 3 &&
  (
    # the full packet looks like what we'd get from running isql.
    (
      getdword(blob:res, pos:4) == 8 && 
      getdword(blob:res, pos:8) == 1 && 
      getdword(blob:res, pos:12) == 3
    )
  )
)
{
  security_hole(port);
}
