#
# This script was written by Jorge E Rodriguez <KPMG>
#
# 
#
# 	- check the system for infected w32.spybot.fbg
#	- script id
#	- cve id
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
 script_id(15520);
 script_version ("$Revision: 1.20 $");
 script_cvs_date("$Date: 2012/09/27 21:29:16 $");
 
 name["english"] = "w32.spybot.fcd Worm Infection Detection";
 script_name(english:name["english"]);
 
 script_set_attribute(
  attribute:"synopsis",
  value:"A worm was detected on the remote Windows host."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote system is infected with a variant of the worm
w32.spybot.fcd.  Infected systems will scan systems that are
vulnerable in the same subnet in order to spread, creating a botnet
that has been used for purposes such as DDoS attacks."
 );
  # http://securityresponse.symantec.com/avcenter/venc/data/w32.spybot.fcd.html
 script_set_attribute(
  attribute:"see_also",
  value:"http://www.nessus.org/u?4420ad95"
 );
 script_set_attribute(
  attribute:"solution",
  value:
"Remove the worm from this system.  Reinstall the operating system if
necessary."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/20");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "Detects if w32.spybot.fcd is installed on the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2012 jorge rodriguez");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "os_fingerprint.nasl");
 script_require_ports(113);
 script_exclude_keys('fake_identd/113');
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include('misc_func.inc');

os = get_kb_item("Host/OS");
if ( os && "Windows" >!< os ) exit(0);

if (get_kb_item('fake_identd/113')) exit(0);

if(get_port_state(113))
{
 soc = open_sock_tcp(113);
 if(soc)
 {
  req = string("GET\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  if(" : USERID : UNIX :" >< r) {
	if ( "GET : USERID : UNIX :" >< r ) exit(0);
	security_hole(113);
	if (service_is_unknown(port: 113))
	  register_service(port: 113, proto: 'fake-identd');
	set_kb_item(name: 'fake_identd/113', value: TRUE);
	}
  close(soc);
 }
}
