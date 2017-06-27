#
# (C) Tenable Network Security, Inc.
#

# Ref: AccessX 

include("compat.inc");

if(description)
{
 script_id(15861);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2004-2474");
 script_bugtraq_id(11748);
 script_osvdb_id(12119);
 
 script_name(english:"PHPNews sendtofriend.php 'mid' Parameter SQLi");
 script_summary(english:"Makes a request to the remote host by supplying the mid parameter in the URL.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP script that is affected by a
SQL injection vulnerability.");
 script_set_attribute(attribute:"description", value:
"The PHPNews application running on the remote web server is affected
by a SQL injection vulnerability due to improper validation of
user-supplied input to the 'mid' parameter tin the sendtofriend.php
script. A remote attacker can exploit this to inject arbitrary SQL
commands.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHPNews 1.2.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/24");

 script_cvs_date("$Date: 2015/06/12 18:55:03 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpnews:phpnews");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var	r, buf;

 r = http_send_recv3(method:"GET", item:string(loc, "/phpnews/sendtofriend.php?mid='1'"), port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if ("mysql_fetch_assoc():" >< buf)
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
