#
# This script was written by Anthony R. Plastino III <tplastino@sses.net>
# Security Engineer with Sword & Shield Enterprise Security, Inc.
#

# Changes by Tenable:
# - Revised plugin title, changed family (8/22/09)


include("compat.inc");

if(description)
{
  script_id(12113);
  script_version ("$Revision: 1.24 $");

  script_cve_id("CVE-2002-0422");
  script_osvdb_id(13431, 13432, 13433);

  script_name(english:"Web Server PROPFIND Method Internal IP Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"This web server leaks a private IP address through its WebDAV
interface." );
 script_set_attribute(attribute:"description", value:
"The remote installation of IIS leaks a private IP address through the
WebDAV interface.  This may expose internal IP addresses that are
usually hidden or masked behind a Network Address Translation (NAT)
Firewall or proxy server. 

This is typical of IIS installations that are not configured properly." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc0a1812" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Mar/101" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c9fccc4" );
 script_set_attribute(attribute:"solution", value:
"Consult Microsoft's KB article for steps to resolve the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/18");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/03/05");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks for private IP addresses in PROPFIND response");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Sword & Shield Enterprise Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

# 
# Now the code
#

if ( egrep(pattern:"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:string(get_host_ip()))) exit(0);

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

sig = get_http_banner(port:port);
if (!sig || "Microsoft-IIS" >!< sig) exit(0);


#
# Build the custom HTTP/1.1 request for the server to respond to
#

soc = http_open_socket(port);
if ( ! soc ) exit(0);

req = string("PROPFIND / HTTP/1.0\r\nHost:\r\nContent-Length: 0\r\n\r\n");
send(socket:soc, data:req);
headers = http_recv_headers2(socket:soc);
stuff = http_recv_body(socket:soc, headers:headers);
http_close_socket(soc);

# 
# now check for RFC 1918 addressing in the returned data - not necessarily in the header
# Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
#
private_ip = eregmatch(pattern:"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})($|[^0-9.])", string:stuff);
if (!isnull(private_ip) && private_ip[0] !~ "Oracle.*10\.")
{
 if (report_verbosity)
 {
   # Avoid too long lines in the report
   if (match(string: stuff, pattern: '<?xml *'))
     stuff = str_replace(string: stuff, find: '><', replace: '>\n<');

  report = string(
   "\n",
   "The remote web server leaks the following private IP address :\n",
   "\n",
   "  ", private_ip[1], "\n",
   "\n",
   "Specifically, when sent the following request :\n",
   "\n",
   req,
   # nb: there's an extra blank line in the request.
   "it responded with :\n",
   "\n",
   stuff
  );
  security_note(port:port, extra:report);
 }
 else security_note(port);
}
