#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30056);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/30 23:05:16 $");

  script_cve_id("CVE-2008-0475");
  script_bugtraq_id(27443);
  script_osvdb_id(42043);

  script_name(english:"ManageEngine Applications Manager Invalid URL Remote Information Disclosure");
  script_summary(english:"Sends an invalid URL to Applications Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Applications Manager installed on the
remote host is affected by an information disclosure vulnerability due
to the application returning a summary of monitor groups and alerts in
response to a request with an invalid URL. A remote attacker, using a
URL with an invalid target location, can exploit this to access
sensitive 'Home->Summary' information about the applications and
services being monitored.

Note that this version may also be affected by several other
information disclosure and cross-site scripting vulnerabilities,
however Nessus did not explicitly check for these issues.");
  # https://packetstormsecurity.com/files/62946/Secunia-Security-Advisory-28332.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c7eb7e6");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch or upgrade details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:applications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("manageengine_applications_manager_detect.nasl");
  script_require_keys("installed_sw/ManageEngine Applications Manager");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "ManageEngine Applications Manager";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9090);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Exploit the issue.
res = http_send_recv3(
  method   : "GET",
  item     : "/-",
  port     : port,
  fetch404 : TRUE,
  exit_on_fail : TRUE
);

# There's a problem if we get to AppManager's Monitor Groups display.
if (
  "title>Applications Manager - Monitor Groups<" >< res[2] &&
  "<!--$Id: Recent" >< res[2]
)
{
  output = strstr(res[2],  "title>Applications Manager");
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    request     : make_list(install_url + "/-"),
    output      : chomp(output)
  );

}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
