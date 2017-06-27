#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (12/30/2008)

include("compat.inc");

if(description)
{
 script_id(18254);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2005-1373");
 script_bugtraq_id(13412, 13413);
 script_osvdb_id(14997);

 script_name(english:"Dream4 Koobi CMS index.php area Parameter SQL Injection");
 script_summary(english:"Checks for a SQL injection in the Koobi CMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the Dream4 Koobi CMS, a CMS written in PHP.

The remote version of this software contains an input validation flaw
leading to a SQL injection vulnerability.  An attacker may exploit
this flaw to execute arbitrary SQL commands against the remote
database.");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2005/Apr/461");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2005/06/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/27");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2016 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("global_settings.inc");
include("http_keepalive.inc");

global_var port;

port = get_http_port(default:80);

function check(url)
{
 local_var req, res;

 req = http_get(item:url +"/index.php?p='nessus", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( isnull(res) ) exit(1, "The web server on port "+port+" failed to respond.");
 if ( 'KOOBI-ERROR' >< res && egrep(pattern:"SQL.*MySQL.* 'nessus", string:res) )
 {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
