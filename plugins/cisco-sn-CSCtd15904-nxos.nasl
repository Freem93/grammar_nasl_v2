#TRUSTED 4e1b94701d319f2e3cd9948f16a5e67ae7e7badb445d2ec017800ada367bb89d9eda1b9d31f30d00726719799338c18b0d3680f27a5912b9ed4e88e626fc7cedd8d38f528f53229cf52506ab6a3b808e8081e5e80f9acb6de4a573ebe4710ac1066dfb85e2e2453419ade49215c112fb47ab65191933e69666a0f3edf1670b1a1efd8ffc34d700db86813e51a49fb96ae1ca7440b543dd75a6cbd0498700694a48c17b1fb67349c4ba162c632631854a19a82c1c642eac4e6ac14ece448aa5ef92ff9faa8f1fd07da5596a36e6eb541a01c5767fefa2d09cc8deb4cd2a58054ba3a7d45b991d95d682c5f03acebcf9e29347825a7debd6019a8264f7a0e6dd88bcff5bef1b4f0591d0cbd81ba3be37d99f8bf520fc0ed165017ed49c45e08486c92d2f58a048c2adf9b9e48c6236fd87f624d7f48e83851cdf34f715fef1363cdd2c085d785ca6df6a77f8c54af791394e5c91d309968a52a7aa18fade094f41f3247c4b5f201bcedf1c3f8367c92975af276f8a47158df85fd0aa1b92f4f0975857e860d0c7fee2a573802c6ac43fdd526485574694be58baae1455ae705debf285cf1f84172aed320be1c7375ad551c15523eb6057962105d8761b8f41f46c5982783e46d909967d3692fbf98ea2f5c8ee9f4eda1e3fd49ed9bdb9b2436d07a749663fecb671964f06b7d37ed9a6946f39fa946bfaee8879212fb94b72dbf0
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2013-6683.  The text itself is copyright (C)
# Cisco.
#

include("compat.inc");

if (description)
{
  script_id(71153);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/10/17");

  script_cve_id("CVE-2013-6683");
  script_bugtraq_id(63685);
  script_osvdb_id(99749);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd15904");

  script_name(english:"Cisco Nexus 4000 Series Switches IPv6 Denial of Service (CSCtd15904)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the IP version 6 (IPv6) packet handling routine of
Cisco NX-OS Software could allow an unauthenticated, adjacent attacker
to cause a device to stop responding to neighbor solicitation (NS)
requests, causing a limited denial of service (DoS) condition.

The vulnerability is due to improper processing of adjacencies in the
IPv6 neighbor table. An attacker could exploit this vulnerability by
sending a sequence of malformed IPv6 packets to an affected device. An
exploit could allow the attacker to cause a device to stop responding
to NS requests, causing a limited DoS condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-6683
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b45fe69b");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Cisco bug ID CSCtd15904.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version","Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# only affects nexus 4000 series systems
if (device != 'Nexus' || model !~ '^4[0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

flag = 0;
override = 0;

if (version =~ "^4\.1\(2\)E1\(1[bdefghij]?\)") flag = 1;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"IPv6\s+is\s+enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  if(report_verbosity > 0)
  {
    report +=
      '\n  Cisco bug ID      : CSCtd15904' +
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
