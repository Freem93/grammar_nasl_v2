#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
#   - revised plugin title, added CVE / OSVDB xrefs, added See also, lowered Risk from Medium (12/11/08)
#   - changed exploit from SQL injection to XSS, which is what these BIDs cover (12/11/08)
#   - revised plugin title, changed family (4/28/09)

include("compat.inc");

if (description)
{
 script_id(19392);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");

 script_cve_id("CVE-2005-2324", "CVE-2005-2325", "CVE-2005-2326");
 script_bugtraq_id(14278, 14395, 14397);
 script_osvdb_id(
  17919,
  18349,
  18350,
  18351,
  18352,
  18353,
  18354,
  18355,
  18356,
  18357,
  18358,
  18359,
  18360,
  18361,
  18509
 );

 script_name(english:"Clever Copy Multiple Vulnerabilities (XSS, Path Disc, Inf Disc)");
 script_summary(english:"Checks for XSS in results.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Clever Copy, a free, fully-scalable web
site portal and news posting system written in PHP

The remote version of this software contains multiple vulnerabilities
that can lead to path disclosure, cross-site scripting and
unauthorized access to private messages.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2de3c207");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6452dc3e" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f8cfd3f" );
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/07");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

# nb: avoid false-positives caused by not checking for the app itself.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/results.php?",
     'searchtype=">', exss, "category&",
     "searchterm=Nessus"
   ),
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( xss >< res )
 {
        security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
 }
}
