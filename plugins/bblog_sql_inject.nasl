#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15466);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2012/11/29 23:28:09 $");

 script_cve_id("CVE-2004-1570");
 script_bugtraq_id(11303);
 script_osvdb_id(10449);
 
 script_name(english:"bBlog rss.php p Parameter SQL Injection");
 script_summary(english:"Check bBlog version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to a SQL injection attack.");
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of bBlog, a blogging system written
in PHP and released under the GPL, which is as old as or older than
version 0.7.4. 

The remote version of this software is affected by a SQL injection
attack in the script 'rss.php'.  This issue is due to a failure of
the application to properly sanitize user-supplied input. 

An attacker may use this flaw to execute arbitrary PHP code on this
host or to take the control of the remote database.");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 0.7.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/13");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:eaden_mckee:bblog");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
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

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port) exit(0);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (make_list(cgi_dirs(),  "/bblog"))
{
 buf = http_get(item:string(dir,"/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"www\.bBlog\.com target=.*bBlog 0\.([0-6]\.|7\.[0-3][^0-9]).*&copy; 2003 ", string:r))
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
}
