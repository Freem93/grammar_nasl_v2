#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76261);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/12 16:40:05 $");

  script_cve_id("CVE-2013-6011");
  script_bugtraq_id(62788);
  script_osvdb_id(98093);

  script_name(english:"Citrix NetScaler nsconfigd Remote DoS (CTX139017)");
  script_summary(english:"Checks Citrix NetScaler version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler version is affected by a remote denial of
service vulnerability in the 'nsconfigd' daemon. An unauthenticated
remote attacker could exploit this issue by sending a specially
crafted message to the daemon, resulting in a reboot of the appliance.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/ctx139017");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Oct/18");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citrix NetScaler 10.0-76.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_application_delivery_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

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

fixed_version = "10.0.76.7";

# only 10.0 is affected
if (version =~ "^10\.0\." && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
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
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

