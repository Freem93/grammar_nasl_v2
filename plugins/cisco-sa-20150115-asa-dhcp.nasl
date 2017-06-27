#TRUSTED 7ce7294f4e55c9e539e479696227f4984d870c9131b3b47809b53ce602a03305bd51dcb74829bb87da5a2b9f0c181d272e9ee0b12743a71444e20d559d20be226c76e419f69698614b86be480864907e854485339d79116dfca41c64953634cb2d661451e9c932e25b7bff5876df51afce9b6466976bf13a9e6a6a5900df953048c87cb477ea4c7502dfd55f8634cb18f5621533e8405fa58b43a80638f0e3842e611c358cbfc31046839611dc9a5eeec11b8ba686b59d935999c8fcff467929764c7dfd260155b68d8d6c98ae886444d6ff59294f43b7b14400fc6bab85b929d8fe0d650f5aabcf15b97b2b452c94b7cdbc7e395f7e6f594d3b59b962bf24c7f557cda973f7562ccb1df9a123deff34cad22236adc5bfef90fd0683b294a710d07f255c7480e4a164c58c517d37c9e524b11ac6d223717a091c924e546b22beb8feee565b4de885c3db7b25b69a6e4024a6a33c6bcaa3c6def6cc97f629fb9883118bbf2db65532f45e9694b747602d9328f949af3f2c55fe571ec09671fbba6d7833e5c62ded950f74d22fbd22ea56abdebbcf28a3e871156c44ab3da27a11367813dc5058632d3bccb003c7828d1fc1451f949cc71c80c949d13009e3a6689c408a1f7062ad030fe1f35fbbb15ca7e619d035a11e66a373c77218d0d1e95350c51fe535ffc9e4fa04aef43863560cd48dc78ac6248a35fa04eb8c524f8993
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86675);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/02/14");

  script_cve_id("CVE-2015-0578");
  script_bugtraq_id(72718);
  script_osvdb_id(117011);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur45455");
  script_xref(name:"CISCO-SA", value: "cisco-sa-20150115-asa-dhcp");

  script_name(english:"Cisco ASA DHCPv6 Relay Function DHCP Packet Handling DoS (CSCur45455)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) device is affected
by a denial of service vulnerability due to improper validation of
DHCPv6 packets by the DHCPv6 relay function. An unauthenticated,
remote attacker can exploit this, via specially crafted DHCPv6
packets, to cause a device reload. ");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150115-asa-dhcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?134984ee");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCur45455.
Alternatively, disable the DHCPv6 relay feature.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/01");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Affected :
# Cisco Adaptive Security Virtual Appliance (ASAv)
# Cisco ASA 1000V Cloud Firewall
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
# Cisco ASA Services Module for Cisco 7600 Series Routers
if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V'
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 or 1000V");

fixed_ver = NULL;

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.37)"))
  fixed_ver = "9.0(4)37";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.21)"))
  fixed_ver = "9.1(5)21";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(2)"))
  fixed_ver = "9.3(2)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if DHCP6 relay is in play
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-ipv6-dhcprelay", "show running-config ipv6 dhcprelay");
  if (check_cisco_result(buf))
  {
    if ("ipv6 dhcprelay enable outside" >< buf) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCP6 relaying is not enabled");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
