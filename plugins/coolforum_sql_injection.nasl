#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16275);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(12392);
 script_osvdb_id(13261);

 script_name(english:"CoolForum Multiple SQL Injections");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP script that is affected by multiple SQL
injection issues." );
 script_set_attribute(attribute:"description", value:
"The version of CoolForum, a bulletin-board application written in PHP,
installed on the remote host fails to sanitize input to several
parameters to scripts in the 'admin' directory before using it in
database queries.  An attacker could leverage these issues to
manipulate SQL queries or attack the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CoolForum 0.7.3 or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/22");
 script_cvs_date("$Date: 2011/03/12 01:05:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of CoolForum";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
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

global_var port;
port = get_http_port(default:80, php:1);

function check(loc)
{
 local_var r;

 r = http_send_recv3(method: 'GET', item:string(loc, "/index.php"), port:port, exit_on_fail: 1);

 if ( egrep(pattern:"Powered by <b>CoolForum v\.0\.([0-6]\..*|7\.[0-2])", string:r[2]) ) 
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
