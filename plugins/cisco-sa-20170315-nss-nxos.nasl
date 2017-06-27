#TRUSTED 9c627874cb2415631905a0823278998ef6bda21fa6a1878d86f9c8e41d9445e19ed8bfee38bd8536ea8d3c2aec376e24d3f7640c9fd65785021892e93496f55deb4fa87a9e94d7eb4dce56b36283968cdf94d7a0089f79175472d3e556a995ac5592975d9c8ce7e1eabb75ffd4e5b256eabac1ddb14a4c83c5d056ce58cb0736e0a7cc5aeb40dfefd3d93736748fa356521563c14588e4cb797442d9b2335b42319acabca39f41de5c8db2886ebcae0cb2bebf878d3666d4ecf62fbba5f179ae1d384438a0ace418c8706b13df60af98f02c3aa24d1d0ed1f310a72cd44c19b15ddd413c2fd3c8bea260653f0bf2b1d3e5f22053ee85e38bfd78dc7ad13ec03958b8f5459beed1bff35485d9cfb4b6f417addea98f69bf6f1a39718514795c27c493eeea23f9ab5a927ef5098b6f520646b3eea98452af41940befe1be26fcff3e6813cbb9c23d1c58e8812537913b6bdbcc69247747dcf3dd98b63b08eedc160e660fa525c1cc15c778a16de24e3cd627b657e80bd613b096b0238b9a50182c008afe66953a5f7b3b4861ee53d6a06d9d77e3fa8acb935bb477d30b564851c6aab5aef7db5b7455d3655354b9a3acb19802f530d4e187cd073633694eb03b78171a1a67658e8714ddea67567c85ecc0e2c19d5f260a05fdc1e47d74cb6ab21af0ed5ec8bec930666424d1df7a5b82da7f1c11939c7a4fd6f700fd33d22b8f9f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99371);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/15");

  script_cve_id("CVE-2017-3878");
  script_bugtraq_id(96927);
  script_osvdb_id(153826);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux46778");
  script_xref(name:"IAVA", value:"2017-A-0096");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170315-nss");

  script_name(english:"Cisco NX-OS Telnet Packet Header Handling Remote DoS (cisco-sa-20170315-nss)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the Telnet remote login functionality due to improper
validation of Telnet packet headers. An unauthenticated, remote
attacker can exploit this, via specially crafted Telnet packets, to
cause the Telnet process to restart.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-nss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ea47371");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux46778.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

flag = 0;
cbid = FALSE;

########################################
# Model 9k
########################################
if (model =~ "^9[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "7.0(3)I3(0.170)") flag = TRUE;
  cbid = "CSCux46778";
}

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

# Check for telnet feature
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^(\s+)?feature telnet", string:buf))
    flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbid
  );
}
else audit(AUDIT_HOST_NOT, "affected");
