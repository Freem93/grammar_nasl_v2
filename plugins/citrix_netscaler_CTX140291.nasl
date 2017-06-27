#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74025);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/12 16:40:05 $");

  script_cve_id("CVE-2014-1899");
  script_bugtraq_id(67177);
  script_osvdb_id(106470);

  script_name(english:"Citrix NetScaler Gateway XSS (CTX140291)");
  script_summary(english:"Checks Citrix NetScaler version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler version is affected by an unspecified
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX140291");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citrix NetScaler 9.3-66.5 or 10.1-123.9 later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_access_gateway_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix NetScaler";
version = get_kb_item_or_exit("Host/NetScaler/Version");
build = get_kb_item("Host/NetScaler/Build");

if (!build)
  exit(0, "The build number of " + app_name + " " + version + " could not be determined.");

display_version = version + "-" + build;
version = version + "." + build;

enhanced = get_kb_item("Host/NetScaler/Enhanced");
if (enhanced) audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version + ".e");

# only 9.x and 10.x are affected
if (version =~ "^9\.")
{
  fixed_version = "9.3.66.5";
}
else if (version =~ "^10\.")
{
  fixed_version = "10.1.123.9";
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
    '\n' +
    '\n' + 'Note: This vulnerability is only present in NetScaler Gateway and may' +
    '\n' + 'not affect your NetScaler device if it does not run NetScaler Gateway.' +
    '\n';
  security_warning(extra:report, port:0);
}
else security_warning(0);
