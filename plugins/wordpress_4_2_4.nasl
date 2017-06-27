#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85243);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/20 04:38:52 $");

  script_cve_id(
    "CVE-2015-2213",
    "CVE-2015-5730",
    "CVE-2015-5732",
    "CVE-2015-5733",
    "CVE-2015-5734"
  );
  script_osvdb_id(
    125761,
    125762,
    125763,
    125764,
    125765
  );

  script_name(english:"WordPress < 4.2.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress application running on
the remote web server is prior to 4.2.4. It is, therefore, potentially 
affected by multiple vulnerabilities :

  - A SQL injection vulnerability exists in the post.php
    script due to a failure to sanitize user-supplied input
    to the 'comment_ID' parameter before using it in SQL
    queries. A remote attacker can exploit this to inject
    SQL queries against the back-end database, allowing
    the disclosure or manipulation of data. (CVE-2015-2213)

  - The class-wp-customize-widgets.php script contains an
    unspecified flaw that allows an attacker to perform a
    side-channel timing attack. No other details are
    available. (CVE-2015-5730)

  - A cross-site scripting vulnerability exists due to the
    default-widgets.php script not validating input to
    widget titles before returning it to users. A remote
    attacker, using a crafted request, can exploit this to
    execute arbitrary script in the user's browser session.
    (CVE-2015-5732)

  - A cross-site scripting vulnerability exists due to the
    nav-menu.js script not validating input to accessibility
    helper titles before returning it to users. A remote
    attacker, using a crafted request, can exploit this to
    execute arbitrary script in the user's browser session.
    (CVE-2015-5733)

  - A cross-site scripting vulnerability exists due to the
    theme.php script not validating input before returning
    it to users. A remote attacker, using a crafted request,
    can exploit this to execute arbitrary script in the
    user's browser session. (CVE-2015-5734)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://codex.wordpress.org/Version_4.2.4");
  # https://wordpress.org/news/2015/08/wordpress-4-2-4-security-and-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e5a0977");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress 4.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/WordPress", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# All versions of WordPress prior to 4.2.4 are vulnerable 
# and according to the release archive 4.2.4, 4.1.7 and 
# 4.0.7 are the highest major, minor and build versions 
# in the 4.x range, to date. WordPress claims that the 
# archive in the link below is a comprehensive list of
# every release that they know of, on record.
# https://wordpress.org/download/release-archive/

if(
  (ver[0] < 4) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 8) ||
  (ver[0] == 4 && ver[1] == 1 && ver[2] < 8) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 4)
  )
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.2.4 ' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);