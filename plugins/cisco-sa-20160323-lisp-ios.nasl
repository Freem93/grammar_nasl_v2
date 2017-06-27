#TRUSTED 78bada5492e9fcfddd1c4ee84f5c2ecc04ef8a5fdd9dc0172099aff60b1290b1bb5c2749d7f6dc7ab949a798516c94b425ff2eebd5b8ac171686fd7248e62b9dd48e98d0b6df2c7ecf04e1171dcd8a307aece78c386fa9409514e0341a40e6159af1dc9fb9ac8f2722318975da5880ca1167249c67374e3bb4dfc59aac393d8de43a6fade841c11ce9b8cbfda59a0c756cf7f50bcc6bf4eddac20e43c557779efbc7e28494c57f6df39c5e6b828b5565c03cd95f37c86cede57928307e74de27673ee6f7df8a295adcbf9510f937ac5b6f51eb98364f75574788afc04163cdd4ebbc519090200d9e5d5e41c95c6f6f8ac1cf7f353a9161b26e4b14a7bca1d2a455b8dbb9a47d0f82f0c15a7e228d78bb3d3ba45c31525487d3105cafef9bcffa21f68d2467f4b3ec756c4bba865154e8b34250f2b4536981a7b760f3a7f63eb52190986054272d03fad021027a6217b905a7d23d8f45b94e15efcacfcda2c1a2a45daa10219a027a45cd687781ce68977af8c1310ffc8161ba49eccdfc8749c92775c35b3f5fae9ee272a202667ac8678a0c2c905a0b29bc5cfadc1548c1af8715bff474a642baa7f246b901d4c64a156690fa14ecab42f2c4a91066e4aa08ccfa3549ec5354df43985f8a1b12cbbfc1dab031adeed3a4d309af4d0195b6f4d3fa86b3457a6f60fbcbbf9508f84fa92dddccbf8db0ed2ce6b635796081ef5558
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90307);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/27");

  script_cve_id("CVE-2016-1351");
  script_bugtraq_id(85309);
  script_osvdb_id(136247);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu64279");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-lisp");

  script_name(english:"Cisco IOS Malformed LISP Packet DoS (CSCuu64279)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS software running on the remote device is
affected by a denial of service vulnerability in the implementation of
the Locator/ID Separation Protocol (LISP) due to improper input
validation when a malformed LISP packet is received. An
unauthenticated, remote attacker can exploit this, via a crafted
packet, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-lisp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3df085d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu64279.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

model   = get_kb_item_or_exit("Host/Cisco/IOS/Model");
if (model !~ '6[58]{1}[0-9][0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, "Catalyst model 6500 / 6800");

flag     = 0;
override = 0;

if (version == "15.1(1)SY1") flag = 1;
else if (version == "15.1(1)SY2") flag = 1;
else if (version == "15.1(1)SY3") flag = 1;
else if (version == "15.1(1)SY4") flag = 1;
else if (version == "15.1(1)SY5") flag = 1;
else if (version == "15.1(1)SY6") flag = 1;
else if (version == "15.1(2)SY") flag = 1;
else if (version == "15.1(2)SY1") flag = 1;
else if (version == "15.1(2)SY2") flag = 1;
else if (version == "15.1(2)SY3") flag = 1;
else if (version == "15.1(2)SY4") flag = 1;
else if (version == "15.1(2)SY4a") flag = 1;
else if (version == "15.1(2)SY5") flag = 1;
else if (version == "15.1(2)SY6") flag = 1;
else if (version == "15.2(1)SY") flag = 1;
else if (version == "15.2(1)SY0a") flag = 1;
else if (version == "15.2(1)SY1")  flag = 1;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_lisp", "show running-config | include lisp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^router lisp(\s|$)", string:buf))
        flag = 1;
    }
    else if (cisco_needs_enable(buf))
    {
      override = 1;
      flag = 1;
    }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCuu64279",
    cmds     : make_list("show running-config | include lisp")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", version);
