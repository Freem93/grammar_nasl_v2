#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18507);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id("CVE-2005-1900", "CVE-2005-1901");
  script_bugtraq_id(13864, 13866, 13868);
  script_osvdb_id(17100, 17101, 17102, 17103);

  script_name(english:"Sawmill < 7.1.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Sawmill.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Sawmill application running on
the remote web server is affected by multiple vulnerabilities :

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to gain administrative privileges.
    (CVE-2005-1900, OSVDB 17100)

  - An unspecified flaw allows an authenticated, remote
    attacker to add an unauthorized license key.
    (CVE-2005-1900, OSVDB 17101)

  - A cross-site scripting vulnerability exists due to
    improper validation of the username variable before
    submitting it to the Add User window. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2005-1901, OSVDB 17102)

  - A cross-site scripting vulnerability exists due to
    improper validation of the license key field before
    submitting it to the Licensing Page. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2005-1901, OSVDB 17103)");
  # https://web.archive.org/web/20070711234617/http://www.networksecurity.fi/advisories/sawmill-admin.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bd7ceaf");
  script_set_attribute(attribute:"see_also", value:"http://www.sawmill.net/version_history7.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sawmill version 7.1.6 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sawmill:sawmill");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("sawmill_detect.nasl");
  script_require_ports("Services/www", 8987, 8988);
  script_require_keys("installed_sw/Sawmill");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Sawmill";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8988, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(qs:dir, port:port);

if (version =~ "^([0-6]\.|7\.(0|1\.[0-5][^0-9.]?))")
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  report =
    '\n  URL               : ' +install_url+
    '\n  Installed version : ' +version+
    '\n  Fixed version     : 7.1.6' +
    '\n';
  security_report_v4(port: port, severity: SECURITY_WARNING, extra: report);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
