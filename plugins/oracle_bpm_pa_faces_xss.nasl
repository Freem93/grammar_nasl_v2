#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48339);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2010-2370");
  script_bugtraq_id(41617);
  script_osvdb_id(66354);
  script_xref(name:"EDB-ID", value:"14369");

  script_name(english:"Oracle BPM Process Administrator tips.jsp context Parameter XSS");
  script_summary(english:"Tries to inject script code via tips.jsp");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a JSP script that is prone to a cross-
site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Oracle Business Process Manager (BPM) Suite's Process
Administrator running on the remote host contains a JSP script -
'webconsole/faces/faces/faces/jsf/tips.jsp' - that fails to sanitize
user input to the 'context' parameter before using it to generate
dynamic HTML output.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.corelan.be:8800/advisories.php?id=CORELAN-10-057");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpujul2010-155308.html");
  script_set_attribute(attribute:"solution", value:"Apply the Oracle July 2010 Critical Patch Update (CPU).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_bpm_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/oracle_bpm");
  script_require_ports("Services/www", 8585, 8686);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:8585);


# Make sure Oracle BPM is indeed installed.
install = get_install_from_kb(appname:'oracle_bpm', port:port, exit_on_fail:TRUE);


# Try to exploit the issue.
alert = "<script>alert('" + SCRIPT_NAME + "')</script>";
cgi = '/faces/faces/faces/jsf/tips.jsp';
dir = '/webconsole';

vuln = test_cgi_xss(
  port     : port,
  cgi      : cgi,
  dirs     : make_list(dir),
  qs       : 'context='+urlencode(str:alert),
  pass_str : '">'+alert+'_TITLE',
  pass2_re : 'tipsHeaderBg|tipsTitle|tipsText'
);
if (!vuln) exit(0, "The Oracle BPM Process Management component at "+build_url(port:port, qs:dir+'/')+" is not affected.");
