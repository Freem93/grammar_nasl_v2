#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55443);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/10/01 01:43:20 $");

  script_bugtraq_id(48348);
  script_osvdb_id(110087);
  script_xref(name:"EDB-ID", value:"17423");

  script_name(english:"WPtouch Plugin for WordPress 'wptouch_redirect' Parameter URL Redirection");
  script_summary(english:"Attempts to redirect to a third-party domain.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that can be abused to
redirect users to an arbitrary URL.");
  script_set_attribute(attribute:"description", value:
"The version of the WPtouch plugin for WordPress installed on the
remote host fails to properly sanitize input to the 'wptouch_redirect'
parameter when 'wptouch_view' is set to 'normal' before using it in
the 'wptouch.php' script to generate a URL redirection.

An attacker can exploit this issue to conduct phishing attacks by
tricking users into visiting malicious websites.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.9.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bravenewcode:wptouch");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "WPtouch";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "wptouch/admin-css/wptouch-admin.css"][0] =
    make_list('WPtouch Admin Panel');

  checks[path + "wptouch/readme.txt"][0] =
    make_list('WPtouch', 'WPtouch is');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext     : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

domain = get_kb_item("Settings/third_party_domain");
if (!domain)domain = "example.com";

url = dir + '/?' +
  'wptouch_view=normal&' +
  'wptouch_redirect=.' + domain;
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

code = hdrs['$code'];
if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# There's a problem if ...
if (
  # we're redirected and ...
  code == 302 &&
  # it's to the location we specified and ...
  '.'+domain >< location &&
  (
    # we're paranoid or ...
    report_paranoia == 2 ||
    # it looks like WPtouch
    hdrs['set-cookie'] && 'wptouch_switch_toggle' >< hdrs['set-cookie']
  )
)
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
