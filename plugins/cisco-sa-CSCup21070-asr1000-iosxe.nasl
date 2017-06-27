#TRUSTED 49a633e545c910fa5fc6f6ad082f041b67468ec710340bae24f461cba0bf61f7664fe5d9425626d4019d73f626763d7a1781d5e60e06e32c5576f4ec2e1f827e7a9a8e047ae7705d9148a2d715ea8657745eeff3af60f4a9df7a07cfaf45878c0dbb09f6ccd2d3f1e73bd80a5389d71e6c7a32e18ec639d9658f04920b725f9e3e1f345b0dbfdfbcb48a54e6e15414b8a6d7444705a66e7c42a04106ad1591ec7a74e8dd9af78c9b12a82cb1fc874f439bf85a334c369ba20e14c101c631c424a75640a65e6cf35031782df72803f82a222dd6582eff2a9a743acff71203dc3c88bf2c2a955412b44ff111551540eba01a53cf26d2a30f0f4a043ad3dcb669d1afda3ec0f6802e5d4f2eeb0cbbf18f6aa8a65fa00c6e23bd0967fcf859c3c1734593728e1feb3d25198309981cb076a9023c97c4ea461e00b500da2e37085cdfce45ff935b2a7a8b7b09dcc740ad1efb61971ac37b98aed46fb7d38ca5314b688d66a720bb677f74863bca961e84cfba2d4b1c8033c4e07e8e708d1fb616c81abb04a7d4ce9672d97c386f04c41180d8a6115519663a72214ef547a624ab9e1b70e0011ff4c14ccb5f08e0dbcf4aff3756ee09bed6fa1fa31d2696dfc2b635f4fd81a02c8c8ef13879931ec4f5352b9550dea9f60d42861e969a7a667f9ca0ce14b15d153b4ca378dd5f02d4aab11211710dd740477e20cea968e79037ae97de
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83871);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0688");
  script_bugtraq_id(73914);
  script_osvdb_id(120295);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup21070");

  script_name(english:"Cisco IOS XE Software for 1000 Series Aggregation Services Routers H.323 DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XE Software for 1000 Series Aggregation Services Routers
(ASR) is affected by a flaw in the Embedded Services Processor (ESP)
due to improper handling of malformed H.323 packets when the device is
configured to use Network Address Translation (NAT). An
unauthenticated, remote attacker by sending malformed H.323 packets,
can exploit this vulnerability to cause a denial of service by
crashing the ESP module.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38210");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant version referenced in Cisco bug ID CSCup21070.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
model = "";

# check hardware
if (get_kb_item("Host/local_checks_enabled"))
{
  # this advisory only addresses CISCO ASR 1000 series
  buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
  if (buf)
  {
    match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
    if (!isnull(match)) model = match[1];
  }
}
if (model !~ '^10[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

cbi       = "CSCup21070";
fixed_ver = "";
flag      = 0;

if (version != "3.10.2S")
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);
else
{
  fixed_ver = "3.10.4S";
  flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_nat_statistics", "show ip nat statistics");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"Total active translations:", string:buf)) &&
           (preg(multiline:TRUE, pattern:"Outside interfaces:", string:buf)) &&
           (preg(multiline:TRUE, pattern:"Inside interfaces:", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report = "";

  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + version +
      '\n  Fixed release     : ' + fixed_ver + '\n';
  }
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
