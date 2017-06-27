#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40578);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2009-2762");
  script_bugtraq_id(36014);
  script_osvdb_id(56971);
  script_xref(name:"EDB-ID", value:"9410");
  script_xref(name:"Secunia", value:"36237");

  script_name(english:"WordPress < 2.8.4 'wp-login.php' 'key' Parameter Remote Administrator Password Reset (uncredentialed check)");
  script_summary(english:"Checks version of WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the version of WordPress running on
the remote server has a flaw in the password reset mechanism.
Validation of the secret user activation key can be bypassed by
providing an array instead of a string. This allows anyone to reset
the password of the first user in the database, which is usually the
administrator. A remote attacker can use this to repeatedly reset the
password, leading to a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Aug/113");
  script_set_attribute(attribute:"see_also", value:"http://core.trac.wordpress.org/changeset/11798");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2009/08/2-8-4-security-release/");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 2.8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(255);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

ver_fields = split(version, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions < 2.8.4 are affected
if (
  major < 2 ||
  (major == 2 && minor < 8) ||
  (major == 2 && minor == 8 && rev < 4)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n URL               : ' + install_url +
      '\n Installed version : ' + version +
      '\n Fixed version     : 2.8.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
