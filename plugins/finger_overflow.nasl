#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(17141);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(2);
 script_osvdb_id(1538);

 script_name(english:"fingerd Remote Overflow");
 script_summary(english:"Sends a long command to fingerd");
 
 script_set_attribute(attribute:"synopsis", value:
"The finger service running on the remote host has a remote buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description",  value:
"Nessus was able to crash the remote finger daemon by sending a very
long request.  This is likely due to a buffer overflow.  A remote
attacker could potentially exploit this to execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://securitydigest.org/unix/archive/037"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this finger daemon."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "1988/11/07");
 script_cvs_date("$Date: 2017/03/21 03:23:57 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "doublecheck_std_services.nasl", "finger.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
include('global_settings.inc');

port = get_kb_item("Services/finger");
if(!port) port = 79;
if(! get_port_state(port)) exit(0, "Port "+port+" is closed.");

soc = open_sock_tcp(port);
if(! soc) exit(1, "Connection to TCP port "+port+" failed.");

send(socket: soc, data: crap(4096)+ '\r\n');
r = recv(socket:soc, length:65535);

close(soc);

sleep(1);

soc = open_sock_tcp(port);
if(! soc) { security_hole(port); exit(0); }
else close(soc);

if (report_paranoia > 1 && ! r)
security_hole(port: port, extra:
"
*** Note that Nessus did not crash the service, so this
*** might be a false positive.
*** However, if the finger service is run through inetd
*** (a very common configuration), it is impossible to 
*** reliably test this kind of flaw.
");
