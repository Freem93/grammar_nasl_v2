#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73226);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/11 21:07:49 $");

  script_cve_id("CVE-2013-4460","CVE-2014-1608", "CVE-2014-1609");
  script_bugtraq_id(63273, 65445, 65461);
  script_osvdb_id(
    98823,
    103118,
    103335,
    103336,
    103337,
    103338,
    103339
  );

  script_name(english:"MantisBT 1.1.0 < 1.2.16 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mantis");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the MantisBT install hosted on the
remote web server is 1.1.0 or later but prior to 1.2.16. It is,
therefore, affected by multiple vulnerabilities:

  - A cross-site scripting flaw exists with the
    'account_sponsor_page.php' where the 'project_id'
    parameter is not validated upon submission. This could
    allow a remote attacker to execute arbitrary script
    code within the browser / server trust relationship
    with a specially crafted request. (CVE-2013-4460)

  - A SQL injection flaw exists in the SOAP API with the
    'db_query()' function where user-supplied input is not
    properly sanitized via the 'mc_issue_attachment_get'
    SOAP request. This could allow a remote attacker to
    inject or manipulate SQL queries, allowing for the
    manipulation or disclosure of arbitrary data. This issue
    affects version 1.1.0a4 or later. (CVE-2014-1608)

  - SQL injection flaws exists in
    'core/news_api.php', 'core/summary_api.php',
    'plugins/MantisGraph/core/graph_api.php',
    'api/soap/mc_project_api.php', and 'proj_doc_page.php'
    pages. This could allow a remote attacker to inject or
    manipulate SQL queries, allowing for the manipulation or
    disclosure of arbitrary data. This issue only affects
    versions 1.2.0 - 1.2.15. (CVE-2014-1609)

Note that Nessus has relied only on the self-reported version number
and has not actually tried to exploit these issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/blog/?p=275");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=16513");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=16879");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=16880");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port, exit_if_unknown_ver:TRUE);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 1.1.0 < 1.2.16 are vulnerable
if (
  (ver[0] == 1 && ver[1] == 1) ||
  (ver[0] == 1 && ver[1] == 2 && ver[2] < 16)
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.2.16\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
