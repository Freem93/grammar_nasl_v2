#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96305);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/06 14:54:12 $");

  script_osvdb_id(
    148128,
    148371,
    148372,
    148373,
    148374
  );
  script_xref(name:"ZDI", value:"ZDI-16-617");

  script_name(english:"Dell SonicWALL Global Management System (GMS) 8.x < 8.2 Multiple Vulnerabilities");
  script_summary(english:"Checks application version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell SonicWALL Global Management System (GMS) running
on the remote host is 8.x prior to 8.2. It is, therefore, affected by
multiple vulnerabilities :

  - A SQL injection (SQLi) vulnerability exists in the
    ImagePreviewServlet servlet due to improper sanitization
    of user-supplied input to the 'logoID' parameter. An
    unauthenticated, remote attacker can exploit this to
    inject or manipulate SQL queries in the back-end
    database, resulting in the manipulation or disclosure of
    arbitrary data. (VulnDB 148128)

  - An unspecified SQL injection (SQLi) vulnerability exists
    due to improper sanitization of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    inject or manipulate SQL queries in the back-end
    database, resulting in the manipulation or disclosure of
    arbitrary data. (VulnDB 148128)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (VulnDB 148372)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to bypass Adobe Flex.
    (VulnDB 148373)

  - An unspecified flaw exists due to improper validation of
    user-supplied input that allows an unauthenticated,
    remote attacker to potentially bypass security filters.
    (VulnDB 148374)");
  script_set_attribute(attribute:"see_also", value:"https://support.sonicwall.com/product-notification/215257");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-617");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell SonicWALL Global Management version 8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2016/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_global_management_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_analyzer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("sonicwall_universal_management_detect.nbin");
  script_require_keys("installed_sw/dell_sonicwall_universal_management_suite");
  script_require_ports("Services/www", 80, 443, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = 'Dell SonicWALL Universal Management Suite';
app_kb   = 'dell_sonicwall_universal_management_suite';
get_install_count(app_name:app_kb, exit_if_zero:TRUE);

fixed_version = '8.2';

port = get_http_port(default:80);
install = get_single_install(app_name:app_kb, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];

# Affected : 8.0 and 8.1
if (version !~ "^8\.[0-1]($|[^0-9])")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(qs:install['path'], port:port), version);
report =
  '\n  Application       : ' + app_name +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fixed_version +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, sqli:TRUE, xss:TRUE);
