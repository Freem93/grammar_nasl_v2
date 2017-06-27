#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description) {
  script_id(19600);
  script_version("$Revision: 1.10 $");

  script_name(english:"MERCUR Messaging Control Server Multiple Buffer Overflows");
  script_summary(english:"Checks for multiple buffer overflows in MERCUR Messaging Control Server");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote administrative system has multiple buffer overflow
vulnerabilities." );
 script_set_attribute( attribute:"description", value:
"The remote host is running MERCUR Messaging Control Server, a
telnet/web server to control MERCUR Messaging software.

According to its banner, the remote version of this software is
vulnerable to multiple buffer overflow vulnerabilities.  A remote
attacker could exploit these flaws by sending specially crafted
packets to port 32000, leading to a denial of service, or possibly
arbitrary code execution." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to MERCUR Messaging 2005+SP3 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/08");
 script_cvs_date("$Date: 2012/09/21 23:16:28 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_require_ports(32000);

  exit(0);
}


port = 32000;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp (port);
if (!soc)
  exit (0);

buf = recv (socket:soc, length:100);
if (!buf || ("MERCUR Control-Service" >!< buf))
  exit (0);

if (egrep (pattern:"^MERCUR Control-Service \(v([0-4]\.|5\.00\.(0[0-9]*|10)( |\)))", string:buf))
  security_hole(port);
