#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77987);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/26 15:02:59 $");

  script_cve_id("CVE-2014-3338");
  script_bugtraq_id(69176);
  script_osvdb_id(109923);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum95491");

  script_name(english:"Cisco Unified Communications Manager 'CTIManager' Remote Command Execution (CSCum95491)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an arbitrary command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device has a flaw in the 'CTIManager'
module that allows a remote, authenticated attacker to execute
arbitrary commands with elevated privileges by using a specially
crafted SSO token.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3338
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7ab717a");
  script_set_attribute(attribute:"solution", value:"Upgrade to a fixed CUCM version listed in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Cisco CTI Manager AND Single Sign On must be enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");

app_name  = "Cisco Unified Communications Manager (CUCM)";

if (ver =~ "^10\.0\." && ver_compare(ver:ver, fix:"10.0.1.13009.1", strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

fixed_ver = "10.0.1.13009-1";

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCum95491'     +
    '\n  Installed release : ' + ver_display +
    '\n  Fixed release     : ' + fixed_ver   +
    '\n';

  security_hole(port:0, extra:report);
}
else security_hole(0);
