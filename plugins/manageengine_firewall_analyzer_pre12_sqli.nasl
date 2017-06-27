#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90446);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_osvdb_id(
    134766,
    134767,
    134768,
    134769,
    134770,
    134771,
    134772,
    134773,
    134774,
    134775,
    134776,
    134992,
    134993,
    134994,
    134995,
    134996,
    134997,
    134998,
    135191
  );
  script_xref(name:"EDB-ID", value:"39477");

  script_name(english:"ManageEngine Firewall Analyzer < 12.0 Multiple Vulnerabilities");
  script_summary(english:"Checks Firewall Analyzer's version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Firewall Analyzer running on the remote
web server is prior to 12.0. It is, therefore, affected by multiple
vulnerabilities :

  - A SQL injection vulnerability exists in the runQuery.do
    script due to improper sanitization of user-supplied
    input to the 'RunQuerycommand' parameter. An
    authenticated, remote attacker can exploit this to
    inject or manipulate SQL queries in the back-end
    database, resulting the manipulation or disclosure of
    arbitrary data. (VulnDB 135191)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input.
    A remote attacker can exploit these vulnerabilities to
    execute arbitrary script code in a user's browser
    session. (VulnDB 134766, VulnDB 134767, VulnDB 134768,
    VulnDB 134769, VulnDB 134770, VulnDB 134771,
    VulnDB 134772, VulnDB 134773, VulnDB 134774,
    VulnDB 134775, VulnDB 134776, VulnDB 134992,
    VulnDB 134993, VulnDB 134994, VulnDB 134995,
    VulnDB 134996, VulnDB 134997, VulnDB 134998)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://packetstormsecurity.com/files/135884/ManageEngine-Firewall-Analyzer-8.5-SQL-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15629b73");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Firewall Analyzer version 12.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zohocorp:manageengine_firewall_analyzer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_firewall_analyzer_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Firewall Analyzer");
  script_require_ports("Services/www", 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

app = "ManageEngine Firewall Analyzer";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8500);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver: TRUE);
url = build_url(port:port, qs:install["path"]);
version = install['version'];

# Confirmed vulnerable range
if (ver_compare(ver:version, fix:"4.0", strict:FALSE) >= 0 && 
    ver_compare(ver:version, fix:"8.5", strict:FALSE) <= 0)
{
  order  = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], url,
    order[1], version,
    order[2], "12.0"
  );
  report = report_items_str(report_items:report, ordered_fields:order);
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
