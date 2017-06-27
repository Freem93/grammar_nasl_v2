#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100416);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/25 15:48:21 $");

  script_cve_id("CVE-2017-6654");
  script_bugtraq_id(98527);
  script_osvdb_id(157721);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc06608");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170517-ucm");
  script_xref(name:"IAVA", value:"2017-A-0156");

  script_name(english:"Cisco Unified Communications Manager XSS (cisco-sa-20170517-ucm)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager (CUCM) running on the remote device is affected
by a cross-site scripting (XSS) vulnerability in the web-based
management interface due to improper validation of user-supplied input
before returning it to users. An unauthenticated, remote attacker can
exploit this, by convincing a user to visit a specially crafted link,
to execute arbitrary script code in the user's browser session.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-ucm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b078838d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc06608/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvc06608.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (ver =~ "^[1-9]\.")
  fix_display = "Refer to Cisco Bug ID CSCvc06608.";
else if (ver =~ "^10\." && ver_compare(ver:ver, fix:'10.5.2.10000.5', strict:FALSE) <= 0)
  fix_display = "Refer to Cisco Bug ID CSCvc06608.";
else if (ver =~ "^11\.0" && ver_compare(ver:ver, fix:'11.0.1.10000.10', strict:FALSE) <= 0)
  fix_display = "Refer to Cisco Bug ID CSCvc06608.";
else if (ver =~ "^11\.5" && ver_compare(ver:ver, fix:'11.5.1.100000.6', strict:FALSE) <= 0)
  fix_display = "Refer to Cisco Bug ID CSCvc06608.";

if (!fix_display)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

order  = make_list('Cisco bug ID', 'Installed release', 'Fixed release');
report = make_array(
  order[0], "CSCvc06608",
  order[1], ver_display,
  order[2], fix_display
);
report = report_items_str(report_items:report, ordered_fields:order);
security_report_v4(extra:report, port:0, severity:SECURITY_WARNING, xss:TRUE);
