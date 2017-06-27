#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# Date: 9 May 2003 16:58:36 -0000
# From: Charles Reinold <creinold@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: ttcms and ttforum exploits
#


include("compat.inc");

if (description)
{
 script_id(11615);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2003-1458", "CVE-2003-1459");
 script_bugtraq_id(7542, 7543);
 script_osvdb_id(54040, 54041, 54042);

 script_name(english:"ttforum Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ttforum.

This set of CGI is vulnerable to various attacks which
may allow an attacker to execute arbitrary code on this
host or gain administrative privileges on this forum." );
 script_set_attribute(attribute:"solution", value:
"Disable this forum or upgrade to a fixed version" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89, 94);


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/10");
 script_cvs_date("$Date: 2016/11/23 20:42:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if ttforum is vulnerable to code injection");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0,"The remote web server does not support PHP.");

# Loop through directories.
if (thorough_tests) dirs =  list_uniq(make_list("/modules/forum", "/ttforum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach d (dir)
{
 url = string(d, '/index.php?board=10;action=news;ext=help;template=http://xxxxxxxxxxxx');
 res = http_send_recv3(method:"GET", item:url, port:port);
 if(isnull(res) ) exit(1,"Null response to index.php request.");
 
 if("php_network_getaddresses: getaddrinfo" >< res[2])
   {
    security_hole(port);
    exit(0);
   }
}
