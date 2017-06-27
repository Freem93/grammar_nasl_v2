#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if(description)
{
 script_id(11784);
 script_cve_id("CVE-2003-1337");
 script_bugtraq_id(8062, 8064);
 script_osvdb_id(50471);

 script_version ("$Revision: 1.17 $");
 script_name(english:"Abyss Web Server GET Request Multiple Vulnerabilities");
 script_summary(english:"Tests the version of the remote Abyss server.");

 script_set_attribute(attribute:"synopsis",value:
"The remote web server is affected by multiple vulnerabilities.");

 script_set_attribute(attribute:"description",value:
"The remote Abyss Web server is earlier than version 1.1.6.  Such
versions are reportedly vulnerable to a buffer overflow that could be
exploited by an attacker to execute arbitrary code on the host. 

In addition, it is possible to inject malicious data into server
response headers using a specially crafted GET request.  An attacker
could use this vulnerability to launch cross-site scripting
attacks.");

 script_set_attribute(attribute:"see_also",value:
"http://seclists.org/bugtraq/2003/Jun/253");

 script_set_attribute(attribute:"solution",value:
"Upgrading to Abyss 1.1.6 or newer is reported to fix the problem.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/30");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

#
# I could not really reproduce the issue with 1.1.5, 
# so I'll stick to a banner check instead
#
banner = get_http_banner(port:port);
if(!banner)exit(0);
if(egrep(pattern:"^Server: Abyss/(0\..*|1\.(0\..*|1\.[0-5])) ", string:banner))
       security_hole(port);
exit(0);       
