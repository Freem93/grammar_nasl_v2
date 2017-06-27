#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14822);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");

 script_bugtraq_id(9303);
 script_osvdb_id(3220);

 script_name(english:"OpenBB board.php FID Parameter XSS");
 script_summary(english:"Tests for XSS flaw in openBB board.php");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to A cross-site scripting
attack.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running OpenBB, a forum management system
written in PHP.

The remote version of this software is vulnerable to cross-site
scripting attacks, through the script 'board.php'.

Using a specially crafted URL, an attacker can cause arbitrary code
execution for third-party users, thus resulting in a loss of integrity
of their system.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/27");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

 script_dependencie("cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port))exit(0);


if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


foreach d (list_uniq(make_list( "/openbb", cgi_dirs())))
{
 req = http_get(item:string(d, "/board.php?FID=%3Cscript%3Efoo%3C/script%3E"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( isnull(res) ) exit(0);
 if(egrep(pattern:"<script>foo</script>", string:res))
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
