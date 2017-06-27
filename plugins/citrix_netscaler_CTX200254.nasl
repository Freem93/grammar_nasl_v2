#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81316);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/13 14:49:08 $");

  script_cve_id("CVE-2014-8580");
  script_bugtraq_id(71350);
  script_osvdb_id(114428);

  script_name(english:"Citrix NetScaler Unspecified Remote Unauthorized Access (CTX200254)");
  script_summary(english:"Checks the Citrix NetScaler version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote unauthorized access
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler device is affected by an unspecified
remote unauthorized access vulnerability in the management interface.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX200254");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix NetScaler 10.1-129.1105.e / 10.1-129.11 / 10.5-52.11
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_application_delivery_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
enhanced = get_kb_item("Host/NetScaler/Enhanced");
fixed_version = NULL;

if (isnull(build)) exit(0, "The build number of " + app_name + " " + version + " could not be determined.");

display_version = version + "-" + build;
version = version + "." + build;

if (!enhanced)
{
  # non-enhanced builds
  if (ver_compare(ver:version, fix:"10.5.50.10") >= 0 &&
      ver_compare(ver:version, fix:"10.5.51.10") <= 0)
  {
    fixed_version = "10.5-52.11";
  }
  else if (ver_compare(ver:version, fix:"10.1.122.17") >= 0 &&
           ver_compare(ver:version, fix:"10.1.128.8") <= 0)
  {
    fixed_version = "10.1-129.11";
  }
}
else
{
  # Enhanced build
  display_version = display_version + ".e";
  if (ver_compare(ver:version, fix:"10.1.120.1316") >= 0 &&
      ver_compare(ver:version, fix:"10.1.128.8003") <= 0)
  {
    fixed_version = "10.1-129.1105.e";
  }
}

if (isnull(fixed_version))
{
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_warning(extra:report, port:0);
}
else security_warning(0);
