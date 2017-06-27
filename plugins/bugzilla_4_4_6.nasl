#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78069);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id("CVE-2014-1571", "CVE-2014-1572", "CVE-2014-1573");
  script_bugtraq_id(70256, 70257, 70258);
  script_osvdb_id(112686, 112687, 112698);

  script_name(english:"Bugzilla < 4.0.15 / 4.2.11 / 4.4.6 / 4.5.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the Bugzilla version number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host contains multiple flaws. It is, therefore, affected by the
following vulnerabilities :

  - If a new comment is marked as private to the insider
    group, and a flag is set in the same transaction, the
    comment will be visible to flag recipients even if they
    are not in the insider group. (CVE-2014-1571)

  - A remote attacker can override certain parameters when
    creating a new Bugzilla account. This can lead to the
    account being created with a different email address
    than originally requested, allowing a user to be added
    to certain groups based on the group's regular
    expression setting. This may allow an attacker to
    escalate a given user accounts privileges.
    (CVE-2014-1572)

  - A flaw existed in how CGI arguments were handled that
    could allow cross-site scripting exploits which an
    attacker could use to access sensitive information.
    (CVE-2014-1573)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.checkpoint.com/blog/bug-bug-tracker/");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/4.0.14/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533628/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 4.0.15 / 4.2.11 / 4.4.6 / 4.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Bugzilla";
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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Versions 2.17.1 to 4.0.14
if (
  version =~ "^2\.(1[7-9]|2[0-9])\." ||
  version =~ "^3\." ||
  version =~ "^4\.0($|\.([0-9]|1[0-4])|rc[12])($|[^0-9])" ||
  version =~ "^4\.1\." || 
  version =~ "^4\.2($|\.([0-9]|10)|rc[12])($|[^0-9])" ||
  version =~ "^4\.3\." || 
  version =~ "^4\.4($|\.[0-5]|rc[12])($|[^0-9])" ||
  version =~ "^4\.5\.[1-5]($|[^0-9])"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed versions    : 4.0.15 / 4.2.11 / 4.4.6 / 4.5.6' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
