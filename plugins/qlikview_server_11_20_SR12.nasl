#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91782);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/27 14:51:42 $");

  script_cve_id("CVE-2015-3623");
  script_osvdb_id(127295);
  script_xref(name:"EDB-ID", value:"38118");

  script_name(english:"QlikView Server AccessPoint XML External Entity Injection");
  script_summary(english:"Checks the version of QlikView Server.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on remote host is affected by an XML
external entity injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of QlikView Server running on the remote host is 11.20
prior to 11.20 SR12. It is, therefore, affected by an XML external
entity (XXE) injection vulnerability, specifically DTD parameter
injection, in the /AccessPoint.aspx script due to an incorrectly
configured XML parser accepting XML external entities from untrusted
sources. An unauthenticated, remote attacker can exploit this, via
crafted XML data, to conduct server-side request forgery (SSRF)
attacks and to read arbitrary files.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://community.qlik.com/blogs/supportupdates/2015/06/09/qlikview-1120-service-release-12-now-available-security-release
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff83979");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Sep/30");
  # https://packetstormsecurity.com/files/133499/Qlikview-11.20-SR4-Blind-XXE-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00d3387a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to QlikView Server version 11.20 SR12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qlik:qlikview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("qlikview_server_webui_detect.nbin");
  script_require_keys("installed_sw/QlikView Server");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "QlikView Server";
fix_service_release = "12";
fix_version = "11.20";
display_fix = "11.20 SR12";

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port);

version = install['version'];
service_release = install['Service Release'];
display_version = version + " SR" + service_release;
url = build_url(port:port, qs:install['path']);

vuln = FALSE;
# Vulnerable Versions: v11.20 SR11 and previous versions
if (ver_compare(ver:version, fix:fix_version, strict:FALSE) < 0)
{
  vuln = TRUE;
}
else if (ver_compare(ver:version, fix:fix_version, strict:FALSE) == 0)
{
  if (ver_compare(ver:service_release, fix:fix_service_release, strict:FALSE) < 0)
    vuln = TRUE;
}

if (vuln)
{
  report = report_items_str(
    report_items:make_array(
      "URL", url,
      "Installed version", display_version,
      "Fixed version", display_fix
    ),
    ordered_fields:make_list("URL", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
} else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, display_version);
