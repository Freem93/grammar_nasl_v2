#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62074);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2012-3981", "CVE-2012-4747");
  script_bugtraq_id(55349);
  script_osvdb_id(85071, 85072);

  script_name(english:"Bugzilla < 3.6.11 / 4.0.8 / 4.2.3 / 4.3.3 Multiple Vulnerabilities");
  script_summary(english:"Checks Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that suffers from
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host is affected by multiple vulnerabilities :

  - When the user logs in using LDAP, the username is not
    escaped when building the uid=$username filter which
    is used to query the LDAP directory. This could
    potentially lead to LDAP injection.  Note that this
    affects versions 2.12 to 3.6.10, 3.7.1 to 4.0.7,
    4.1.1 to 4.2.2, and 4.3.1 to 4.3.2. (CVE-2012-3981)

  - Extensions are not protected against directory
    browsing and users can access the source code of the
    templates which may contain sensitive data.  Note that
    this affects versions 2.23.2 to 3.6.10, 3.7.1 to 4.0.7,
    4.1.1 to 4.2.2, and 4.3.1 to 4.3.2. (CVE-2012-4747)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.6.10/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Bugzilla 3.6.11/ 4.0.8 / 4.2.3 / 4.3.3 or later. Note that
a patch for CVE-2012-4747 may not have been ported to all branches of
Bugzilla. Please refer to the above referenced URL for available
patches and solutions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];

install_loc = build_url(port:port, qs:dir + "/query.cgi");

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions less than 3.6.11 / 4.0.8 / 4.2.3 / 4.3.3 are vulnerable
# Specific ranges were provided by bugzilla.org/security/3.6.10/
if (
  # 2.12 to 3.6.10
  (ver[0] == 2 && ver[1] > 11) ||
  (ver[0] == 3 && ver[1] < 6) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 11) ||

  # 3.7.1 to 4.0.7
  (ver[0] == 3 && ver[1] == 7 && ver[2] > 0) ||
  (ver[0] == 3 && ver[1] > 7) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 8) ||

  # 4.1.1 to 4.2.2
  (ver[0] == 4 && ver[1] == 1 && ver[2] > 0) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 3) ||

  # 4.3.1 to 4.3.2
  (ver[0] == 4 && ver[1] == 3 && ver[2] > 0 && ver[2] < 3)
)

{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.6.11 / 4.0.8 / 4.2.3 / 4.3.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
