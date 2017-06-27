#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99706);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/26 15:50:24 $");

  script_cve_id("CVE-2017-3808");
  script_bugtraq_id(97922);
  script_osvdb_id(155949);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz72455");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-ucm");

  script_name(english:"Cisco Unified Communications Manager SIP UDP Throttling DoS (CSCuz72455)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager (CUCM) running on the remote device is affected
by a denial of service vulnerability in the Session Initiation
Protocol (SIP) UDP throttling process due to insufficient rate
limiting protection. An unauthenticated, remote attacker can exploit
this, by sending a high rate of SIP messages, to cause the device to
reload unexpectedly.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-ucm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2de6197");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz72455/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Unified Communications Manager version
10.5(2.14900.16) / 11.0(1.23900.5) / 11.5(1.12900.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

# "This vulnerability affects Cisco Unified Communications Manager (CallManager) releases prior to the first fixed release"
if (ver =~ "^[1-9]\.")
  fix_display = "10.5(2.14900.16)";
else if (ver =~ "^10\." && ver_compare(ver:ver, fix:'10.5.2.14900.16', strict:FALSE) < 0)
  fix_display = "10.5(2.14900.16)";
else if (ver =~ "^11\.0" && ver_compare(ver:ver, fix:'11.0.1.23900.5', strict:FALSE) < 0)
  fix_display = "11.0(1.23900.5)";
else if (ver =~ "^11\.[1-5]" && ver_compare(ver:ver, fix:'11.5.1.12900.2', strict:FALSE) < 0)
  fix_display = "11.5(1.12900.2)";

if (!fix_display)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

order  = make_list('Cisco bug ID', 'Installed release', 'Fixed release');
report = make_array(
  order[0], "CSCuz72455",
  order[1], ver_display,
  order[2], fix_display
);
report = report_items_str(report_items:report, ordered_fields:order);
security_report_v4(extra:report, port:0, severity:SECURITY_HOLE);
