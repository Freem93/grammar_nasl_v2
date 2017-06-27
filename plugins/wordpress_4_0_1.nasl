#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79437);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_cve_id(
    "CVE-2014-9031",
    "CVE-2014-9032",
    "CVE-2014-9033",
    "CVE-2014-9034",
    "CVE-2014-9035",
    "CVE-2014-9036",
    "CVE-2014-9037",
    "CVE-2014-9038",
    "CVE-2014-9039"
  );
  script_bugtraq_id(71231, 71232, 71233, 71234, 71236, 71237, 71238);
  script_osvdb_id(114855, 114856, 114857, 114858, 114859, 114860, 114861);
  script_xref(name:"EDB-ID", value:"35413");
  script_xref(name:"EDB-ID", value:"35414");

  script_name(english:"WordPress < 3.7.5 / 3.8.5 / 3.9.3 / 4.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the WordPress application installed
on the remote web server is affected by multiple vulnerabilities :

  - Multiple unspecified errors exist that could allow
    cross-site scripting attacks.

  - An unspecified error exists that could allow cross-site
    request forgery attacks.

  - An error exists related to password handling that could
    allow denial of service attacks.

  - An unspecified error exists that could allow server-side
    request forgery attacks.

  - A hash collision error exists that could allow a user
    account to be compromised.

  - An error exists related to password reset processing
    that could allow a user account to be compromised.

  - An error exists related to the post or page comment
    field that could allow persistent cross-site scripting
    attacks.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/news/2014/11/wordpress-4-0-1/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.7.5");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.8.5");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.9.3");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_4.0.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.7.5 / 3.8.5 / 3.9.3 / 4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 3.7.5 / 3.8.5 / 3.9.3 / 4.0.1 are vulnerable
# https://wordpress.org/download/release-archive/
if (
  # Short versions
  version == "3.7" || version == "3.8" ||
  version == "3.9" || version == "4.0" ||
  # Longer versions
  (ver[0] < 3) ||
  (ver[0] == 3 && ver[1] < 7) ||
  (ver[0] == 3 && ver[1] == 7 && ver[2] < 5) ||
  (ver[0] == 3 && ver[1] == 8 && ver[2] < 5) ||
  (ver[0] == 3 && ver[1] == 9 && ver[2] < 3) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 1) ||
  # Short beta / RC versions
  version =~ "^(3\.[789]|4\.0)-(beta|RC)\d($|[^0-9])" ||
  # Longer beta / RC versions
  version =~ "^(3\.7\.5|3\.8\.5|3\.9\.3|4\.0\.1)-(beta|RC)\d($|[^0-9])"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.7.5 / 3.8.5 / 3.9.3 / 4.0.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
