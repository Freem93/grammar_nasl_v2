#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11607);
 script_bugtraq_id(7332);
 script_cve_id("CVE-2003-0134");
 script_osvdb_id(9713);
 script_version("$Revision: 1.22 $");
 
 script_name(english:"Apache 2.0.x < 2.0.46 on OS/2 filestat.c Device Name Request DoS");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.0.x that
is prior to 2.0.46 on OS/2. There is a vulnerability specific to such
versions running on OS/2 in 'filestat.c' that could allow an attacker
to disable this service remotely.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 2.0.46 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/21" );
 script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.0");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/02");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-3][0-9]|4[0-5]) .OS/2.", string:serv))
 {
   security_warning(port);
 }
