#TRUSTED 43cac23bebd6fe4e2638a7058ad2843ccd381918a8d3ebed3e76b5e7bb63af45571a116e30fae223da7117e648b1f98b91f0bf6cf148b276acf12248be260593a138fa306b39ee60439a83e847ea47393ea6c81a5fbf53acb4e85c4cecf0dad72a64dc58f64228e3a92e6bb24e644fa3e74a425017148fdeffdc2cf56d0503a0d11905ff779468b17955859f04b08ef4b4aaaf2654fa9be80ea734339fda1727e11a71cc396d9924efa42d23c1028857970c2dd92b3f27bb0b719bdba1be0ad0403c6d22cb23c52ccabd730c95e086de2186cf5855f494f8334ec8590d36cf9a65c6dc0887919cf760199c4add8c6637fb2a88331118640ac332a7fe416e1a8d3765f1410edebae85ca7d49f3b2aa9903b41ceea57656ee104e9bcb45e7a57f92c088fa0c0a2a0af9c9d10a1de0d37b2f0df768437360581efa41aa577f9680bdebc27e53f98837ef3c5d82e07f1fa9a1130e8b358a83497b39345fe13b56b919771c8f0fa6a4f9230a35c87bb9cf128496ea7dcfe6d2bd920a7133a98442f2c1dccf54f961c3c62cf8a8b16191070e99f29ef4be51774b54f5be325292c6d1c37c1b7d796abd0b5933b92f37327b2764ec48bd43b3d9bcedede33539cbeb7af0e5cf0fd2560da5b42a2000cfa3e0a861af5f828f4058fcc7b4c3da7a4f66de628b3e137f09127b6d5e395f60c7869f81e1a007ad364372a07575df0e4546ccb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95257);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/25");

  script_cve_id("CVE-2015-6393");
  script_bugtraq_id(93419);
  script_osvdb_id(145214);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq39250");
  script_xref(name:"IAVA", value:"2016-A-0274");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus21733");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus21739");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut76171");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux67182");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-dhcp2");

  script_name(english:"Cisco NX-OS DHCPv4 Crafted Packet DoS (cisco-sa-20161005-dhcp2)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the DHCPv4 relay agent due to improper validation of
DHCPv4 packets. An unauthenticated, remote attacker can exploit this,
via a specially crafted DHCPv4 packet, to cause the affected device to
reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-dhcp2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20f16ba1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20161005-dhcp2.");
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
  else if (version =~ "^6\.0")
    fix = "6.0(2)N2(7)";
  else if (version =~ "^7\.0")
    fix = "7.0(6)N1(1)";
  else if (version =~ "^7\.1")
    fix = "7.1(1)N1(1)";
  else if (version =~ "^7\.2")
    fix = "7.2(0)N1(1)";
  else if (version =~ "^7\.3")
    fix = "7.3(0)N1(1)";
}
########################################
# Model 3k
########################################
else if (model =~ "^3[0-9][0-9][0-9][0-9]?([^0-9]|$)")
{
  if (model =~ "^35[0-9][0-9]([^0-9]|$)")
    fix = "6.0(2)A6(6)";
  else if (version =~ "^[0-6]([^0-9])")
    fix = "6.0(2)U6(6)";
  else if (version =~ "^7\.0([^0-9])")
    fix = "7.0(3)I2(2b)";
}
########################################
# Model 7k
########################################
else if (model =~ "^7[0-9][0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^[0-6]([^0-9])")
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
    fix = "7.0(3)I2(2b)";
  else if (version =~ "^11\.")
    fix = "11.1";
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
    bug_id   : "CSCuq39250, CSCus21733, CSCus21739, CSCut76171, CSCux67182",
    override : override
  );
}
else audit(AUDIT_HOST_NOT, "affected");
