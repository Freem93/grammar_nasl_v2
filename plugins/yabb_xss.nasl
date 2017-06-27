#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14782);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/11/01 20:05:52 $");

 script_cve_id("CVE-2004-2402", "CVE-2004-2403");
 script_bugtraq_id(11214, 11215);
 script_osvdb_id(10242, 10243);

 script_name(english:"YaBB 1 GOLD SP 1.3.2 Multiple Vulnerabilities");
 script_summary(english:"Checks YaBB.pl XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that suffers from
multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The 'YaBB.pl' CGI is installed. This version is affected by a
cross-site scripting vulnerability. This issue is due to a failure of
the application to properly sanitize user-supplied input.

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed.

Another flaw in YaBB may allow an attacker to execute malicious
administrative commands on the remote host by sending malformed IMG
tags in posts to the remote YaBB forum and waiting for the forum
administrator to view one of the posts.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/226");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/21");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:yabb:yabb");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/yabb", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (cgi_dirs())
{
 req = string(dir, "/YaBB.pl?board=;action=imsend;to=%22%3E%3Cscript%3Efoo%3C/script%3E");
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( isnull(r) )exit(0);
 if (egrep(pattern:"<script>foo</script>", string:r))
 {
       security_note(port);
       set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
       exit(0);
 }
}
