#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93939);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-6420");
  script_bugtraq_id(78872);
  script_osvdb_id(129952, 130424, 131470);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux34835");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151209-java-deserialization");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Cisco Unified Communications Manager Java Object Deserialization RCE (CSCux34835)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified
Communications Manager (CUCM) running on the remote device is affected
by a remote code execution vulnerability due to unsafe deserialize
calls of unauthenticated Java objects to the Apache Commons
Collections (ACC) library. An unauthenticated, remote attacker can
exploit this, via crafted Java objects, to execute arbitrary code on
the target host.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-java-deserialization
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94b4a89a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux34835/");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Unified Communications Manager version 9.1(2)SU5 /
10.5(2)SU3a / 11.0(1a)SU2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

# No fix for 8
if (ver =~ "^[1-8]\.")
  fix_display = "9.1(2)su5 / 9.1(2.15126.1)";
else if (ver =~ "^9\."  && ver_compare(ver:ver, fix:'9.1.2.15126.1', strict:FALSE) < 0)
  fix_display = "9.1(2)su5 / 9.1(2.15126.1)";
else if (ver =~ "^10\." && ver_compare(ver:ver, fix:'10.5.2.14065.1', strict:FALSE) < 0)
  fix_display = "10.5(2)su3a / 10.5(2.14065.1)";
else if (ver =~ "^11\." && ver_compare(ver:ver, fix:'11.0.1.22041.1', strict:FALSE) < 0)
  fix_display = "11.0(1a)su2 / 11.0(1.22041.1)";

if (!fix_display)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

order  = make_list('Cisco bug ID', 'Installed release', 'Fixed release');
report = make_array(
  order[0], "CSCux34835",
  order[1], ver_display,
  order[2], fix_display
);
report = report_items_str(report_items:report, ordered_fields:order);
security_report_v4(extra:report, port:0, severity:SECURITY_HOLE);
