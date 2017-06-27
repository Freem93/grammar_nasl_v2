#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15451);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/07/11 14:12:51 $");

 script_cve_id("CVE-2004-1588", "CVE-2004-1589");
 script_bugtraq_id(11361);
 script_osvdb_id(10641, 10642, 10643, 10644);

 script_name(english:"GoSmart Message Board Multiple Vulnerabilities (SQLi, XSS)");
 script_summary(english:"Checks GoSmart message board flaws");

 script_set_attribute(attribute:"synopsis", value:"A remote CGI is vulnerable to several flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host is running GoSmart message board, a bulletin board
manager written in ASP.

The remote version of this software contains multiple flaws, due to a
failure of the application to properly sanitize user-supplied input.

It is also affected by a cross-site scripting vulnerability. As a
result of this vulnerability, it is possible for a remote attacker to
create a malicious link containing script code that will be executed
in the browser of an unsuspecting user when followed.

Furthermore, this version is vulnerable to SQL injection flaws that
let an attacker inject arbitrary SQL commands.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the newest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/11");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:gosmart:gosmart_message_board");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/ASP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if (!get_port_state(port))exit(0);
if ( ! can_host_asp(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/messageboard/Forum.asp?QuestionNumber=1&Find=1&Category=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E%3C%22");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (egrep(pattern:"<script>foo</script>", string:r))
 {
       security_hole(port);
       set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
       set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
       exit(0);
 }
}
