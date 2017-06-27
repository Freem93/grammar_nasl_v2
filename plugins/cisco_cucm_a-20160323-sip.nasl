#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90312);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id("CVE-2016-1350");
  script_bugtraq_id(85372);
  script_osvdb_id(136248);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv39370");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-sip");

  script_name(english:"Cisco Unified Communications Manager SIP Memory Leak DoS (CSCuv39370)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager (CUCM) running on the remote device is affected
by a denial of service vulnerability in the Session Initiation
Protocol (SIP) gateway implementation due to improper handling of
malformed SIP messages. An unauthenticated, remote attacker can
exploit this, via crafted SIP messages, to cause memory leakage,
resulting in an eventual reload of the affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddc3f527");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCuv39370");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Unified Communications Manager version 9.1(2)SU4 /
10.5(2)SU3 / 11.0(1)SU1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");
fix_display = FALSE;
app_name    = "Cisco Unified Communications Manager (CUCM)";

if (ver =~ "^8\." && ver_compare(ver:ver, fix:'8.6.1.20015.1', strict:FALSE) < 0)
  fix_display = "8.6(1.20015.1)";
else if (ver =~ "^8\.6\.2\." && ver_compare(ver:ver, fix:'8.6.2.26169.1', strict:FALSE) < 0)
  fix_display = "8.6(2.26169.1)";
else if (ver =~ "^9\."  && ver_compare(ver:ver, fix:'9.1.2.14102.1', strict:FALSE) < 0)
  fix_display = "9.1(2)su4 / 9.1(2.14102.1)";
else if (ver =~ "^10\." && ver_compare(ver:ver, fix:'10.5.2.13033.1', strict:FALSE) < 0)
  fix_display = "10.5(2)su3 / 10.5(2.13033.1)";
else if (ver =~ "^11\." && ver_compare(ver:ver, fix:'11.0.1.21006.1', strict:FALSE) < 0)
  fix_display = "11.0(1)su1 / 11.0(1.21006.1)";

if (!fix_display)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

order  = make_list('Cisco bug ID', 'Installed release', 'Fixed release');
report = make_array(
  order[0], "CSCuv39370",
  order[1], ver_display,
  order[2], fix_display
);
report = report_items_str(report_items:report, ordered_fields:order);
security_report_v4(extra:report, port:0, severity:SECURITY_HOLE);
