#TRUSTED 599cefc09b3aaaedf7d4d10ba265a26132540f7f5ca845b2fcbc5927cedb78e484af2fc247453b615ddee32a214e89470334e7f8f2160da9b5f0629e019b2279e2e8e16b227458f996854371220bc5f6fe9e97cdf8bf6d00248627db0e4fe5a5d0efd9fd7cf8cea235f31d799718ad8ee5344b1da19b2ddb4496c4d52b707e4eb2cda72c60f1d400825303a197d04094f72e95c0c7b3472c88d7bbe58fe8fcfb4a707d235d9c56d6f06598d432f5b3a6243ec61b8e9695f48d6bdd78bbf5357a1cabaaeba1d043e05fbf4744f272442606ac0681c4de0b4a9fb5dfcdc86531ba21db3fc6995957467391f4dd12716fa4712c9cfa97282da08ed783ecb0be3081703dad1ec35eb31db122aea7a90a7844494d066ff61a913aa959adf26e74016fa90d6727876d96240dc7b87450fbfd0aa3c77ea52d9401699de29f39805b0c97c00e76e3855be9478249b9c15aafaffd62ef76dba2acfd5b4cc172aaeb2625b6b7924b6c7eb45d6b5073e7d7016a6174bfa0f1df093f0844bcc560f2c82dd36fe7bd79d0df4507524ff91881c5e5c7d28259f9a256900e17fae0262865be42d69c031d7406fa08e1d7eb34d2f7803097ce0391ef3c404232cd84aab2b0f375b25836a92f1782f768346655f260d1140e9f267aec2695054d7bd53cc731175ea8dd47ba9d99a07d06202feeac7d4aa0b689a0f53f029f8ec74a9a724184d658a4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95256);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/25");

  script_cve_id("CVE-2015-6392");
  script_bugtraq_id(93406);
  script_osvdb_id(145183);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq24603");
  script_xref(name:"IAVA", value:"2016-A-0274");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur93159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus21693");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut76171");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-dhcp1");

  script_name(english:"Cisco NX-OS DHCPv4 Crafted Packet DoS (cisco-sa-20161005-dhcp1)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the DHCPv4 relay agent and smart relay agent due to
improper validation of DHCPv4 packets. An unauthenticated, remote
attacker can exploit this, via a specially crafted DHCPv4 packet, to
cause the affected device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-dhcp1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f80fa40");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20161005-dhcp1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
override = 0;
fix = NULL;

########################################
# Model 5000
########################################
if (model =~ "^50[0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^([0-4]|5\.[0-2])([^0-9])")
    fix = "5.2(1)N1(9)";
}
########################################
# Models 2k, 5500, 5600, 6k
########################################
else if (model =~ "^([26][0-9]|5[56][0-9]?)[0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^([0-4]|5\.[0-2])([^0-9])")
    fix = "5.2(1)N1(9)";
  else if (version =~ "^6\.0([^0-9])")
    fix = "6.0(2)N2(7)";
  else if (version =~ "^7\.0([^0-9])")
    fix = "7.0(6)N1(1)";
  else if (version =~ "^7\.1([^0-9])")
    fix = "7.1(1)N1(1)";
  else if (version =~ "^7\.2([^0-9])")
    fix = "7.2(0)N1(1)";
  else if (version =~ "^7\.3([^0-9])")
    fix = "7.3(0)N1(1)";
}
########################################
# Model 7k
########################################
else if (model =~ "^7[0-9][0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^[0-6]\.")
    fix = "6.2(16)";
  else if (version =~ "^7\.2([^0-9])")
    fix = "7.2(0)D1(1)";
  else if (version =~ "^7\.3([^0-9])")
    fix = "7.3(0)D1(1)";
}
########################################
# Model 9k
########################################
else if (model =~ "^9[0-9][0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^(6\.1|7\.0)([^0-9]|$)")
    fix = "7.0(3)I1(1)";
  else if (version =~ "^11\.")
    fix = "11.1(1)";
}
else audit(AUDIT_HOST_NOT, "an affected model");

# Check if version is below the fix available
if (!isnull(fix) && cisco_gen_ver_compare(a:version, b:fix) < 0)
  flag = TRUE;
else audit(AUDIT_HOST_NOT, "an affected NXOS release");

# Check for DHCP configured
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_dhcp", "show running | include dhcp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip dhcp relay", multiline:TRUE, string:buf)) { flag = TRUE; }
      else audit(AUDIT_HOST_NOT, "affected due to vulnerable feature not enabled");
    }
    else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    version  : version,
    bug_id   : "CSCuq24603, CSCur93159, CSCus21693, CSCut76171",
    override : override
  );
}
else audit(AUDIT_HOST_NOT, "affected");
