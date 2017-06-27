#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78893);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2014-7140");
  script_bugtraq_id(70696);
  script_osvdb_id(113579);

  script_name(english:"Citrix NetScaler Unspecified Remote Code Execution (CTX200206)");
  script_summary(english:"Checks the Citrix NetScaler version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler device is affected by an unspecified
remote code execution vulnerability in the management interface.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX200206");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citrix NetScaler 10.1-129.11 / 10.5-50.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_application_delivery_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
  fixed_version = "10.1.129.11";
}
else if (version =~ "^10\.5\." || version =~ "^10\.0\.")
{
  # 10.5 or 10.0
  fixed_version  = "10.5.50.10";
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
}

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

if (report_verbosity > 0)
{
  display_fixed = ereg_replace(string:fixed_version, pattern:"^([0-9]+\.[0-9]+)\.(.*)$", replace:"\1-\2");
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fixed +
    '\n';
  security_hole(extra:report, port:0);
}
else security_hole(0);
