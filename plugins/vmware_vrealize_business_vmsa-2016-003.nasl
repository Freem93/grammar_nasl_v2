#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90351);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id("CVE-2016-2075");
  script_osvdb_id(135901);
  script_xref(name:"VMSA", value:"2016-0003");

  script_name(english:"VMware vRealize Business Unspecified Stored XSS (VMSA-2016-0003)");
  script_summary(english:"Checks the version of vRealize Business.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by a
stored cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Business running on the remote host is
8.x prior to 8.2.5. It is, therefore, affected by a stored cross-site
scripting vulnerability due to improper validation of user-supplied
input. An authenticated, remote attacker can exploit this issue, via a
specially crafted request, to execute arbitrary script code in a 
user's browser session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0003.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Business version 8.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_business");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_vrealize_business_webui_detect.nbin");
  script_require_keys("installed_sw/VMware vRealize Business");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "VMware vRealize Business";
fix = "8.2.5";

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:app, port:port);

version = install['version'];
url = build_url(port:port, qs:install['path']);

# only 8.x is vuln
if (version !~ "^8\.")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = report_items_str(
    report_items:make_array(
      "URL", url,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("URL", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_NOTE, xss:TRUE, extra:report);
} else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
