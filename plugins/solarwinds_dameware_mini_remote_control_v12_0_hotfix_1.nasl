#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86994);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id("CVE-2015-8220");
  script_bugtraq_id(77549);
  script_osvdb_id(130093);
  script_xref(name:"ZDI", value:"ZDI-15-555");
  script_xref(name:"IAVB", value:"2015-B-0137");

  script_name(english:"SolarWinds DameWare Mini Remote Control < 12.0 Hotfix 1 DWRCC.exe RCE");
  script_summary(english:"Checks the version of DameWare Mini Remote Control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote management application that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of SolarWinds DameWare Mini
Remote Control prior to 12.0 Hotfix 1. It is, therefore, affected by
a remote code execution vulnerability due to a flaw in the DWRCC.exe
URI handler that is triggered when handling certain command line
arguments. An unauthenticated, remote attacker can exploit this by
convincing a user to follow a link containing a crafted command line
argument, resulting in a stack-based buffer overflow and the execution
of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://thwack.solarwinds.com/message/308973");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-555/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds DameWare Mini Remote Control v12.0 Hotfix 1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:solarwinds:dameware_mini_remote_control");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_dameware_mini_remote_control_installed.nbin");
  script_require_keys("installed_sw/SolarWinds DameWare Mini Remote Control");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "SolarWinds DameWare Mini Remote Control";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
version = install['version'];
fix = "12.0.0.514";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
