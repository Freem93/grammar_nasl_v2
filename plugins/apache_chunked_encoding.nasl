#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11030);
 script_version("$Revision: 1.52 $");
 script_cve_id("CVE-2002-0392");
 script_bugtraq_id(5033);
 script_osvdb_id(838);

 script_name(english:"Apache Chunked Encoding Remote Overflow");
 script_summary(english:"Checks for version or behavior of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a remote code execution attack." );
 script_set_attribute(attribute:"description", value:
"The remote Apache web server is affected by the Apache web server
chunk handling vulnerability. 

If safe checks are enabled, this may be a false positive since it is
based on the version of Apache. Although unpatched Apache versions
1.2.2 and above, 1.3 through 1.3.24, and 2.0 through 2.0.36 are
affected, the remote server may be running a patched version of
Apache." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 1.3.26 / 2.0.39 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Apache Win32 Chunked Encoding');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/info/security_bulletin_20020617.txt" );
 script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/info/security_bulletin_20020620.txt" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/19");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

# We can keep the old HTTP API for this kind of test
include("global_settings.inc");
include("http_func.inc");
include("backport.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Apache" >!< sig ) exit(0);

if(get_port_state(port))
{
 failed = "";
 if(!safe_checks() && report_paranoia > 1)
 {
 req = string("GET /index.nes HTTP/1.0\r\n",
		"Transfer-Encoding: chunked\r\n\r\n",
		"1\r\n",
		crap(2), "\r\n\r\n");	
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   init = recv_line(socket:soc, length:4096);
   http_close_socket(soc);
   
 
   soc = http_open_socket(port);
   if ( ! soc ) exit(0);
   if(ereg(pattern:"^HTTP/1\.[0-1] [0-9]* ", string:init))
   {
    # This was a real web server. Let's try again, with malicious data
    req = string("GET /index.nes HTTP/1.0\r\n",
		"Transfer-Encoding: chunked\r\n\r\n",
		"fffffff0\r\n",
		crap(42), "\r\n\r\n");
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    if(ereg(string:r, pattern:"HTTP/1\.[01] [234][0-9][0-9] "))exit(0);
    #display(r);
    for(i=0;i<10;i=i+1)
     {
      # If there is a send error, then it means the remote host
      # abruptly shut the connection down
      n = send(socket:soc, data:crap(5));
      sleep(1);
      if(n < 0)
       {
       security_hole(port);
       exit(0);
       }
      }
    }
    http_close_socket(soc);
  }
  failed = "*** Note : Nessus's attempts to 'exploit' this vulnerability failed.";
 }
 

 banner = get_backport_banner(banner:get_http_banner(port: port));
 
 serv = strstr(banner, "Server");
 if(ereg(pattern:"^Server:.*IBM_HTTP_SERVER/1\.3\.(12\.7|19\.[3-9]|2[0-9]\.)", string:serv))exit(0);
 if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-5]))|2\.0.([0-9][^0-9]|[0-2][0-9]|3[0-8]))", string:serv))
 {
   report = NULL;
   if(strlen(failed))
   {
     report = string("\n\n", failed, "\n\n");
   }
   security_hole(port:port, extra:report);
 }
}
