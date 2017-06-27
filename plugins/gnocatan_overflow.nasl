#
# (C) Tenable Network Security, Inc.
#

# Ref: http://www.debian.org/security/2003/dsa-315

include("compat.inc");

if (description)
{
 script_id(11736);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2014/05/26 00:12:07 $");

 script_cve_id("CVE-2003-0433");
 script_bugtraq_id(7877);
 script_osvdb_id(6684);

 script_name(english:"gnocatan Multiple Buffer Overflows");
 script_summary(english:"Checks if the remote Gnocatan Server can be overflown");

 script_set_attribute(attribute:"synopsis", value:"The remote game server is affected by a buffer overflow.");
 script_set_attribute(attribute:"description", value:
"The remote host is running gnocatan, an online game server.

There is a flaw in this version which may allow an attacker to execute
arbitrary commands on this host, with the privileges this service is
running with.

An attacker may exploit this flaw to gain a shell on this host.");
 script_set_attribute(attribute:"solution", value:"Upgrade to gnocatan 0.6.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencies("find_service2.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/gnocatan", 5556);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/gnocatan");
if(!port)port = 5556;
if ( ! get_port_state(port) ) exit(0);


soc = open_sock_tcp(port);
if(!soc)exit(0);
r = recv_line(socket:soc, length:4096);
if("version report" >< r)
{
 if(safe_checks())
 {
  report = "
*** As safe checks are enabled, Nessus did not check for this
*** vulnerability but solely relied on the presence of the service
*** to issue this alert";



  security_hole(port:port, extra:report);
  exit(0);
 }

 send(socket:soc, data:'version ' + crap(4096) + '\n');
 r = recv_line(socket:soc, length:4096);
 if(strlen(r))exit(0);
 close(soc);

 soc = open_sock_tcp(port);
 if(!soc) { security_hole(port); exit(0); }
 r = recv_line(socket:soc, length:4096);
 if(!r) { security_hole(port); }
 close(soc);
}
