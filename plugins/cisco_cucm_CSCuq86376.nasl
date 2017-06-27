#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80283);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2014-7991");
  script_bugtraq_id(71013);
  script_osvdb_id(114486);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq86376");

  script_name(english:"Cisco Unified Communications Manager TLS SAN Field MitM (CSCuq86376)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device is affected by a security bypass
vulnerability due to improper validation of the SAN field in TLS
certificates. A remote attacker can impersonate a Cisco TelePresense
Video Communication Server (VCS) core device to perform
man-in-the-middle (MitM) attacks.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-7991
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?571ec9b9");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=36381");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the Cisco bug advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");
app_name    = "Cisco Unified Communications Manager (CUCM)";

fixed_ver = "10.5.2.10000-2";

if (ver_compare(ver:ver, fix:"10.5.2.10000.2", strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCuq86376'     +
    '\n  Installed release : ' + ver_display +
    '\n  Fixed release     : ' + fixed_ver   +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
