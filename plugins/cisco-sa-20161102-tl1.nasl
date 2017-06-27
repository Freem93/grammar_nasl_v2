#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94680);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/09 22:38:11 $");

  script_cve_id("CVE-2016-6441");
  script_bugtraq_id(94072);
  script_osvdb_id(146614);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161102-tl1");
  script_xref(name:"IAVA", value:"2017-A-0002");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy15175");

  script_name(english:"Cisco IOS XE TL1 Request Handling RCE (cisco-sa-20161102-tl1)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model, the Cisco IOS XE
software running on the remote ASR device is affected by a remote code
execution vulnerability in the Transaction Language 1 (TL1) code due
to an overflow condition caused by improper bounds checking on certain
input when handling TL1 requests. An unauthenticated, remote attacker
can exploit this, via a specially crafted request to the TL1 port, to
cause a denial of service condition or the execution of arbitrary
code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-tl1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cb66121");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy15175");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy15175. Alternatively, as a mitigation, deploy infrastructure
access control lists (iACLs) to prevent TL1 packets from reaching the
device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check model
# Affected: ASR902, ASR903, ASR907
model = get_kb_item("CISCO/model");
if(empty_or_null(model)) model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if(model && model !~ "^ASR90[237]([^0-9]|$)") audit(AUDIT_DEVICE_NOT_VULN, model);

app = "Cisco IOS XE";
cbi = "CSCuy15175";
fix = NULL;

if (
  ver == "3.17.0S" ||
  ver == "3.17.1S" ||
  ver == "3.17.2S"
)
  fix = '3.17.3S';
if (
  ver == "3.18.0S" ||
  ver == "3.18.1S"
)
  fix = '3.18.2S';

if(!empty_or_null(fix))
{

  security_report_cisco(
  port     : 0,
  severity : SECURITY_HOLE,
  version  : ver,
  bug_id   : cbi,
  fix      : fix
  );

}
else audit(AUDIT_HOST_NOT, "affected");
