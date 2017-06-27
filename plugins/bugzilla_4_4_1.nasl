#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70720);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id(
    "CVE-2013-1733",
    "CVE-2013-1734",
    "CVE-2013-1742",
    "CVE-2013-1743"
  );
  script_bugtraq_id(63197, 63199, 63204, 63205);
  script_osvdb_id(98679, 98680, 98681, 98682);

  script_name(english:"Bugzilla < 4.0.11 / 4.2.7 / 4.4.1 Multiple Vulnerabilities");
  script_summary(english:"Checks Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that suffers from
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host is affected by multiple vulnerabilities :

  - A cross-site request forgery vulnerability exists due to
    a flaw in token validation in 'process_bug.cgi'.  Note
    that this only affects versions 4.4rc1 to 4.4.
    (CVE-2013-1733)

  - A cross-site request forgery vulnerability exists due to
    a flaw in the validation of HTTP requests when updating
    attachments with the 'attachment.cgi' script.  Note that
    this affects versions 2.16rc1 to 4.0.10, 4.1.1 to 4.2.6,
    and 4.3.1 to 4.4. (CVE-2013-1734)

  - A cross-site scripting vulnerability exists due to
    improper parameter validation in 'editflagtypes.cgi'.
    Note that this affects versions 2.17.1 to 4.0.10, 4.1.1
    to 4.2.6, and 4.3.1 to 4.4. (CVE-2013-1742)

  - A cross-site scripting vulnerability exists due to
    incorrectly filtered field values in tabular reports.
    Note that this affects 4.1.1 to 4.2.6 and 4.3.1 to 4.4.
    (CVE-2013-1743)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/news/#release441");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/529262/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=911593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=913904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=924802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=924932");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 4.0.11 / 4.2.7 / 4.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

# Versions less than 4.0.11 / 4.2.7 / 4.4.1 are vulnerable
if (
  version =~ "^2\.(1[6-9]|2[0-2])($|\.[0-9]+|rc[12])" ||
  version =~ "^3\." ||
  version =~ "^4\.0($|\.([0-9]|10)$|rc[12])" ||
  version =~ "^4\.[13]\." ||
  version =~ "^4\.2($|\.[0-6]$|rc[12])" ||
  version =~ "^4\.4($|rc[12])"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 4.0.11 / 4.2.7 / 4.4.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
