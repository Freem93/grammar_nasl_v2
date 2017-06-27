#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76916);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/12 16:40:05 $");

  script_cve_id("CVE-2014-4346", "CVE-2014-4347");
  script_bugtraq_id(68535, 68537);
  script_osvdb_id(109173, 109174);

  script_name(english:"Citrix NetScaler Multiple Vulnerabilities (CTX140863)");
  script_summary(english:"Checks the Citrix NetScaler version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler version is affected by multiple
vulnerabilities :

  - A reflected cross-site-scripting in the administration
    user interface. (CVE-2014-4346)

  - A cookie information disclosure vulnerability.
    (CVE-2014-4347)");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX140863");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citrix NetScaler 10.1-126.12 or 9.3-62.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_application_delivery_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix NetScaler";
version = get_kb_item_or_exit("Host/NetScaler/Version");
build = get_kb_item("Host/NetScaler/Build");

if (!build) exit(0, "The build number of " + app_name + " " + version + " could not be determined.");

display_version = version + "-" + build;
version = version + "." + build;

enhanced = get_kb_item("Host/NetScaler/Enhanced");
if (enhanced) audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version + ".e");

if (version =~ "^10\.1\.")
{
  # 10.1
  fixed_version = "10.1.126.12";
}
else if (version =~ "^9\.3\.")
{
  # 9.3
  fixed_version  = "9.3.62.4";
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
}

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

set_kb_item(name:'www/0/XSS', value:TRUE);

if (report_verbosity > 0)
{
  display_fixed = ereg_replace(string:fixed_version, pattern:"^([0-9]+\.[0-9]+)\.(.*)$", replace:"\1-\2");
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fixed +
    '\n';
  security_warning(extra:report, port:0);
}
else security_warning(0);
