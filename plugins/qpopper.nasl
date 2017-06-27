#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10196);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2014/05/26 15:42:19 $");

 script_cve_id("CVE-1999-0006");
 script_bugtraq_id(133);
 script_osvdb_id(912);

 script_name(english:"Qpopper PASS Command Remote Overflow");
 script_summary(english:"Qpopper buffer overflow");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"There is a bug in some versions of Qpopper which allows a remote user
to become root using a buffer overflow.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of Qpopper.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/06/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("popserver_detect.nasl");
 script_require_ports("Services/pop3", 110);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"pop3", default: 110, exit_on_fail: 1);

if (safe_checks())
{
 banner = get_kb_item("pop3/banner/"+port);
 if (! banner && thorough_tests)
 {
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  banner = recv_line(socket:soc, length:4096);

  if("QPOP" >< banner)
  {
   if(ereg(pattern:".*version (1\..*)|(2\.[0-4])\).*",
   	   string:banner))
	   {
	    security_hole(port:port);
	   }
  }
 }
 exit(0);
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

soc = open_sock_tcp(port);
if(!soc)exit(0);
buf = recv_line(socket:soc, length:4095);
if(!strlen(buf)){
	set_kb_item(name:"pop3/"+port+"/false_pop3", value:TRUE);
 	close(soc);
	exit(0);
	}
if ( "QPOP" >!< buf )
{
 close(soc);
 exit(0);
}

command = strcat(crap(4095), '\r\n', buf);
send(socket:soc, data:command);
buf2 = recv_line(socket:soc, length:5000);
buf3 = recv_line(socket:soc, length:4095);

send(socket:soc, data: 'QUIT\r\n');
r = recv(socket:soc, length:4096);
len = strlen(r);
if(!len)
{
 security_hole(port);
}
close(soc);

