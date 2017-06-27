#TRUSTED 5a7df063b918739db13d951a438d446f1f37afcdc6d653f4d71821f5e57aed537367cda58d308da5a705582670c5632cec509c0d0c77661fbd29823958419f39486f7f2a5f7433092a07234c1f4681fc3554a386d4028816429e69585cdec2bd0cbea3681da36c5f0a0f9b1ecea72e1f153c3c05b1c3be39b118327e5cb985f3dc8760a85e5aa86a927004ac8e99e83c7f0c46c6d99203bfe8fe29c7e88e9b53b7e7deea058f1c696d95dda9ae3f553d1b12ff1757d785e4397e742bbb6d63e45c07ee8b3c03e4cd652e476e71bb903b9079b0fca1f8144abde19b9b32558ddc164a4356fad65a8ba84869ff7b165b5b952e4f91b27e774a9731cfbff482461d3b95d44f9c1dd29eec7d9734bca467181c49b4ab6a2c079595829060120d6f68da47b52dfface6e1fd9be6954ffdcd18fec1de2ec6815135710cf3e7decbb1110a3052ab16fd1c351ee51ecae9637d01e98c4070a5f6ecc11185f23068c2cac95ddfca6abeea0b41afacc44cd62c7850765cb050c46c563900f3379d2f6617af138174f85cd78680c7992fa740ddae138ec89d8ca6578de55f25f386948b9ffe9ce21df425038486e60650d819ddc27d368f07c581d94fc0999fdf510c7fe8693dd9e4e8dbe255227f97e06ccb79cd4e2b23be10024b8905cf16c326df59926126f0d06291c5722b6659e044f902be21bfef252eb31871b9f6eeec4e73f66db8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91855);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/27");

  script_cve_id("CVE-2014-2146");
  script_osvdb_id(138980);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun96847");

  script_name(english:"Cisco IOS-XE Zone-Based Firewall Feature Security Bypass (CSCun96847)");
  script_summary(english:"Checks the IOS-XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS-XE software
running on the remote device is affected by a security bypass
vulnerability in the Zone-Based Firewall feature due to insufficient
zone checking for traffic belonging to existing sessions. An
unauthenticated, remote attacker can exploit this, by injecting
spoofed traffic that matches existing connections, to bypass security
access restrictions on the device and gain access to resources.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun96847");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=39129");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.
Alternatively, disable the Zone-Based Firewall feature according to
the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

# Fix version = 3.15.0S
if (
  ver =~ "^[0-2](\.[0-9]+){0,2}[a-z]*S" ||
  ver =~ "^3\.[0-9](\.[0-9]+)?[a-z]*S" ||
  ver =~ "^3\.1[0-4](\.[0-9]+)?[a-z]*S"
) flag++; # version affected

if (flag > 0 && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  # verify zone-based firewall is enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_zone_security", "show zone security");
  if (check_cisco_result(buf))
  {
    if (preg(pattern:"Member Interfaces:", multiline:TRUE, string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCun96847' +
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : See solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
