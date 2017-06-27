#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16320);
 script_cve_id("CVE-2005-0368");
 script_bugtraq_id(12457);
 script_osvdb_id(13573, 13574);
 
 script_version ("$Revision: 1.19 $");
 script_name(english:"Chipmunk CMScore Multiple Script SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple SQL injection vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Chipmunk CMScore, a web-based software
written in PHP. 

The remote version of this software is affected by several SQL
injection vulnerabilities that may allow an attacker to execute
arbitrary SQL statements using the remote SQL database." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Feb/87" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/05");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks if Chipmunk CMScore is vulnerable to a SQL injection attack");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 if ( is_cgi_installed3(item:dir + "/index.php", port:port) )
 {
   r = http_send_recv3( port: port, method: 'POST', item: dir + "/index.php", 
 data: "searchterm='&submit=submit",
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded") );

   if (isnull(r)) exit(0);
   if ("<table border='0' width='90%'><tr><td valign='top' width='75%' align='center'><br><br>dies" >< r[2] )
   {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit(0);
   }
  }
}
