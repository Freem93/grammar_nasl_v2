#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57979);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/03/04 16:15:43 $");

  script_cve_id("CVE-2012-0085");
  script_bugtraq_id(51457);
  script_osvdb_id(78405);

  script_name(english:"Oracle WebCenter Content Help Component XSS");
  script_summary(english:"Checks the content of frameset.htm");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains several scripts that are susceptible
to reflected cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Oracle WebCenter Content is susceptible to multiple reflected cross-
site scripting attacks in the help component including 'frameset.htm',
'api.htm', 'switch.js', and 'wwhsec.htm'.

By tricking someone into clicking on a specially crafted link, an
attacker may be able exploit this to inject arbitrary HTML and script
code in a user's browser to be executed within the security context of
the affected site."
  );
  # http://ausdetica.tmpsvr5.co.uk/Research/Advisories/Oracle-Fusion-Middleware-%28Oracle-WebCenter-Content.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f19d081");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");
  script_set_attribute(
    attribute:"solution",
    value:
"See the Oracle advisory for information on obtaining and applying bug
fix patches."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_webcenter_content_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Oracle WebCenter Content");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app_name = "Oracle WebCenter Content";

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app_name, port:port);

dir = install['path'];

install_url = build_url(port: port, qs:dir);

vuln_page = "/help/user_help/wwhelp/wwhimpl/common/html/frameset.htm";

url = dir + vuln_page;
url_report = url + '#?"&&"JavaScript:alert(/Cross-site-scripting/.source)';

res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

# We have to look and see if the page has the vulnerable JavaScript code
if (
  'var  WWHFrameReference = "window.frames[1]";' >< res[2] &&
  'Parts = location.href.split("?");' >< res[2] &&
  'Parameters = "?" + Parts[1];' >< res[2] &&
  'setTimeout(WWHFrameReference + ".location.replace(\\"switch.htm" + Parameters + "\\");", 1);' >< res[2] &&
  # filter parameters (help system vendor fix)
  'Parameters = Parameters.replace(/[\\\\<>:;"\']|%5C|%3C|%3E|%3A|%3B|%22|%27/gim, "");' >!< res[2] &&
  # ensure comment is not broken so code can't run (seen in some oracle fix packs)
  res[2] =~ '<!--[\r\n ]*// Set reference to top level help frame'
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
    '\n' + 'The following request can be used to verify the vulnerability :' +
    '\n' +
    build_url(port:port, qs:url_report) +
    '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
