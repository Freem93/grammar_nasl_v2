#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19750);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2005-2989");
 script_bugtraq_id(14851);
 script_osvdb_id(19404, 19405, 19406, 19407, 19408);
 script_xref(name:"Secunia", value:"16819");
 
 script_name(english:"DeluxeBB Multiple Scripts SQL Injection");
 script_summary(english:"Checks DeluxeBB version");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP application that is affected by
multiple SQL injection flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host is using DeluxeBB, a web application forum written in
PHP. 

The installed version of this software fails to sanitize input to
several parameters and scripts before using it to generate SQL
queries.  Provided PHP's 'magic_quotes_gpc' setting is disabled, an
attacker may be able to leverage these issues to manipulate database
queries.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to DeluxeBB version 1.05 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2005/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/15");
 script_cvs_date("$Date: 2011/11/28 21:39:45 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
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

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

function check(loc, port)
{
 local_var r, req;

 req = http_get(item:string(loc, "/topic.php?tid='select"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if(isnull(r))exit(0);
 if (("Error querying the database" >< r) && ("DeluxeBB tried to execute: SELECT" >< r))
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir, port:port);
}
