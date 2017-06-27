#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70091);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/03 04:40:26 $");

  script_cve_id("CVE-2013-3462");
  script_bugtraq_id(61913);
  script_osvdb_id(96489);
  script_xref(name:"CISCO-BUG-ID", value:"CSCud54358");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130821-cucm");

  # 7.1(x) < 7.1(5b)su6 / 8.5(x) < 8.5(1)su6 / 8.6(x) < 8.6(2a)su3 / 9.x < 9.1(2)
  script_name(english:"Cisco Unified Communications Manager Remote Buffer Overflow (CSCud54358)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device is affected by a remote buffer
overflow vulnerability that allows an authenticated, remote attacker
to corrupt data, disrupt services, or execute arbitrary commands.");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=30434
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?273e52bc");

  script_set_attribute(attribute:"solution", value:
"For Cisco Unified Communications Manager (CUCM) 7.1(x), upgrade to
version 7.1(5b)su6 or later. For 8.5(x), upgrade to version 8.5(1)su6
or later. For 8.6(x), upgrade to 8.6(2a)su3 or later. For 9.x, upgrade
to 9.1(2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
fixed_ver = NULL;

if (ver =~ "^7\.1\." && ver_compare(ver:ver, fix:"7.1.5.35900", strict:FALSE) < 0)
  fixed_ver = "7.1(5b)su6";
# The fix exist in name only, so we compare to the last broken (8.5(1)SU5).
else if (ver =~ "^8\.5\." && ver_compare(ver:ver, fix:"8.5.1.15900", strict:FALSE) <= 0)
  fixed_ver = "8.5(1)su6";
else if (ver =~ "^8\.6\." && ver_compare(ver:ver, fix:"8.6.2.23900", strict:FALSE) < 0)
  fixed_ver = "8.6(2a)su3";
else if (ver =~ "^9\." && ver_compare(ver:ver, fix:"9.1.2.10000", strict:FALSE) < 0)
  fixed_ver = "9.1(2)";
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCub35869'     +
    '\n  Installed release : ' + ver_display +
    '\n  Fixed release     : ' + fixed_ver   +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
