#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70092);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/03 04:40:26 $");

  script_cve_id("CVE-2013-3459");
  script_bugtraq_id(61911);
  script_osvdb_id(96486);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf93466");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130821-cucm");

  script_name(english:"Cisco Unified Communications Manager Registration Messages DoS (CSCuf93466)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device improperly handles registration
messages, allowing an unauthenticated, remote attacker to cause a
denial of service condition.");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=30431
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?478649a8");

  script_set_attribute(attribute:"solution", value:
"Upgrade Cisco Unified Communications Manager to version 7.1(5b)su6a or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");

app_name  = "Cisco Unified Communications Manager (CUCM)";
fixed_ver = "7.1.5.35901.1";

# Vulnerability is applicable only to 7.1.
if (ver !~ "^7\.1\." || ver_compare(ver:ver, fix:fixed_ver, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

report = NULL;
if (report_verbosity > 0)
{
  # We give the version numbers with the in-house build number.
  report =
    '\n  System version      : ' + ver_display +
    '\n  Fixed CUCM version  : 7.1(5b)su6a'  +
    '\n';

  security_hole(port:0, extra:report);
}
else security_hole(0);
