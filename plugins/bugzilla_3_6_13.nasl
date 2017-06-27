#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64878);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2013-0785", "CVE-2013-0786");
  script_bugtraq_id(58001, 58060);
  script_osvdb_id(90397, 90404);

  script_name(english:"Bugzilla < 3.6.13 / 4.0.10 / 4.2.5 / 4.4rc2 Multiple Vulnerabilities");
  script_summary(english:"Checks Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that suffers from
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host is affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability exists due to a
    flaw in the validation of the 'id' parameter upon
    submission of the 'show_bug.cgi' script.  An attacker
    can leverage this to inject arbitrary HTML and script
    code in a user's browser to be executed within the
    security context of the affected site.  Note that this
    affects versions 2.0 to 3.6.12, 3.7.1 to 4.0.9,
    4.1.1 to 4.2.4, and 4.3.1 to 4.4rc1.
    (CVE-2013-0785)

  - An information leak issue exists when running a query
    in debug mode.  This can lead to the display of the
    SQL query used to collect the data.  Confidential
    information could be leaked in the SQL query that is
    displayed.	Note that this affects versions 2.17.1 to
    3.6.12, and 3.7.1 to 4.0.9.  (CVE-2013-0786)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=842038");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.6.12/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 3.6.13 / 4.0.10 / 4.2.5 / 4.4rc2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

# Versions less than 3.6.13 / 4.0.10 / 4.2.5 / 4.4rc2 are vulnerable
# Specific ranges were provided by bugzilla.org/security/3.6.12/
if (
  # 2.0 to 3.6.12
  (ver[0] == 2 && ver[1] >= 0) ||
  (ver[0] == 3 && ver[1] < 6) ||
  (ver[0] == 3 && ver[1] == 6 && ver[2] < 13) ||

  # 3.7.1 to 4.0.9
  (ver[0] == 3 && ver[1] == 7 && ver[2] > 0) ||
  (ver[0] == 3 && ver[1] > 7) ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 10) ||

  # 4.1.1 to 4.2.4
  (ver[0] == 4 && ver[1] == 1 && ver[2] > 0) ||
  (ver[0] == 4 && ver[1] == 2 && ver[2] < 5) ||

  # 4.3.1 to 4.4rc1
  (ver[0] == 4 && ver[1] == 3 && ver[2] > 0) ||
  (version =~ "^4\.4rc1")
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.6.13 / 4.0.10 / 4.2.5 / 4.4rc2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
