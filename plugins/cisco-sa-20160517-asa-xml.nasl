#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91946);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/29 16:12:04 $");

  script_cve_id("CVE-2016-1385");
  script_osvdb_id(138645);
  script_bugtraq_id(90721);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160517-asa-xml");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut14209");

  script_name(english:"Cisco Adaptive Security Appliance XML Parser DoS (cisco-sa-20160517-asa-xml)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Adaptive Security Appliance (ASA) Software running on the
remote device is affected by a denial of service vulnerability in the
XML parser feature due to improper hardening of the XML parser
configuration. An authenticated, remote attacker can exploit this, via
a specially crafted XML file, to crash the XML parser process, causing
the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160517-asa-xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34c4079f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut14209.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/05");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Affected :
# All Cisco Adaptive Security Appliance releases are affected by this vulnerability

fixed_ver = NULL;

# Cisco ASA Major Release      First Fixed Release
# Prior to 9.0    Affected. Migrate to 9.1(7.6) or later
# 9.0             Affected. Migrate to 9.1(7.6) or later
# 9.1      9.1(7.6)
# 9.2      9.2(4.8)
# 9.3      9.3(3.8)
# 9.4      9.4(2.6)
# 9.5      9.5(2.6)
# 9.6      Not affected
if ((ver =~ "^[0-8]\.")  || (ver=~ "^9\.0") || ((ver =~ "^9\.1[^0-9]") && check_asa_release(version:ver, patched:"9.1(7.6)")))
  fixed_ver = "9.1(7.6)";
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4.8)"))
  fixed_ver = "9.2(4.8)";
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.8)"))
  fixed_ver = "9.3(3.8)";
else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(2.6)"))
  fixed_ver = "9.4(2.6)";
else if (ver =~ "^9\.5[^0-9]" && check_asa_release(version:ver, patched:"9.5(2.6)"))
  fixed_ver = "9.5(2.6)";
else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

order = make_list('Installed version', 'Fixed version');
report = make_array(
  order[0], ver,
  order[1], fixed_ver
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
