#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93048);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-6355");
  script_bugtraq_id(92399);
  script_osvdb_id(142802);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160810-iosxr");
  script_xref(name:"IAVB", value:"2016-B-0130");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux26791");

  script_name(english:"Cisco IOS XR 5.1.x < 5.1.3 / 5.2.x < 5.2.4 / 5.3.x < 5.3.2 Fragmented Packet DoS (cisco-sa-20160810-iosxr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XR that is
5.1.x prior to 5.1.3, 5.2.x prior to 5.2.4, or 5.3.x prior to 5.3.2.
It is, therefore, affected by a denial of service vulnerability in the
driver processing functions due to improper processing of fragmented
packets. An unauthenticated, remote attacker can exploit this to cause
a memory leak on the route processor (RP), resulting in the device
dropping all control-plane protocols.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160810-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fe90a65");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux26791");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux26791.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "CISCO/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model = get_kb_item_or_exit("CISCO/model");

if (model !~ "^ciscoASR9001") audit(AUDIT_HOST_NOT, "an affected model");

# Affected versions include :
#  - 5.1.x < 5.1.3
#  - 5.2.x < 5.2.4
#  - 5.3.x < 5.3.2
if (version !~ "^5\.(1\.[0-2]|2\.[0-3]|3\.[01])([^0-9]|$)")
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

report =
  '\n  Cisco bug ID      : CSCux26791' +
  '\n  Installed release : ' + version +
  '\n  Fixed release     : 5.1.3 / 5.2.4 / 5.3.2' +
  '\n';
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
