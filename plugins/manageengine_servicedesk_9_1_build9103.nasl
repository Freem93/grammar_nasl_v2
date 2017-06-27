#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85599);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_osvdb_id(
    125612,
    125613,
    125614,
    125615,
    125616,
    125617,
    125618,
    125619,
    125620,
    125621,
    125622,
    125623
  );

  script_name(english:"ManageEngine ServiceDesk Plus 9.1.0 < Build 9103 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ManageEngine ServiceDesk Plus.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running ManageEngine ServiceDesk Plus version 9.1.0
prior to build 9103. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input on the
    'Login' page. A remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code. (VulnDB 125612)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input when adding
    new software license types or options. A remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code. (VulnDB 125613)

  - An unspecified flaw exists in the file attachment URL
    on the software details page. (VulnDB 125614)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input when sending
    reports by email. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code. (VulnDB 125615)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    'module' and 'from' parameters when completing the 'Add
    new task' action. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code. (VulnDB 125616)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    'UNIQUE_ID' parameter in the 'Solution' module. A remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code.
    (VulnDB 125617)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the email
    notification window. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code. (VulnDB 125618)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input to the
    request template, reminder, and technician calendar. A
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code.
    (VulnDB 125619)

  - A security bypass vulnerability exists due to an
    unspecified flaw. An authenticated, remote attacker can
    exploit this to update incident details. (VulnDB 125620)

  - A security bypass vulnerability exists due to an
    unspecified flaw. An authenticated, remote attacker can
    exploit this to access problem and change details.
    (VulnDB 125621)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code.
    (VulnDB 125622)

  - A SQL injection vulnerability exists due to improper
    sanitization of user-supplied input before using it in
    SQL queries. A remote attacker can exploit this to
    inject or manipulate SQL queries, resulting in the
    manipulation or disclosure of arbitrary data.
    (VulnDB 125623)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.manageengine.com/products/service-desk/readme-9.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ServiceDesk Plus version 9.1.0 build 9103 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:servicedesk_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_servicedesk_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/manageengine_servicedesk");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");
include("url_func.inc");

appname = "manageengine_servicedesk";
disname = "ManageEngine ServiceDesk";

get_install_count(app_name:appname, exit_if_zero:TRUE);

port    = get_http_port(default:8080);
install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url     = build_url(port:port, qs:install['path']);
build   = eregmatch(string:version, pattern:"[B|b]uild ([0-9]+)");
if(empty_or_null(build))
  audit(AUDIT_VER_NOT_GRANULAR, disname, version);
build   = int(build[1]);

if(version =~ "^9\.1(\.| )" && build < 9103)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 9.1 Build 9103' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xss:TRUE, sqli:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, disname, url, version);
