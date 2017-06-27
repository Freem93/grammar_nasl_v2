#TRUSTED 3c57886dca7df055719ac47d8828a4c7aea8693344822fa37a44c99e1b320814f826d708a0b8b56b7090a7f754a56d51711d734a7df3431d92df01479c690f1ce9744570baa99dbe12a1bcb1c1d3356d2c8e2618d36db4c723baff25064067da4c9a4b7750eab31a80399f8800fdd54106a9f64fb980a2b21ab622242cd9dbd3dc1b1de1d817315e3918c925946487cef6cfd746bc5d4a0371e3a1baf53775d0f7ccde1afe91b13163cfeab2b3f2e9714d5b3986936520a6a1d209e2346809f0c072f958b44784e07e537d79f78c728c7b5f81d55d7f83d7d5e218b78fc3d479e29d93f7cb3a4a964ba478c056f426f1697f5aca7a055c4fc75acbd8bb36c134393e08a63ba6530549d27bcbd8e279f70bbaa48e62a51a7c3697b6b24c71273a8eb6281073c87f8ee362667482de5ff4e6536b6c6a70a08df0b98ef1d2ba51cda5b1cf3cefbc9664410c859487c2e13d4f6d290af1d5ea4ced69815d88b54bce883d253517bdd8fe9951e6f572b86c9e0a6f0d64e5e860e37e3e7c5254067f97c8e435a1ada99b85212ff0e6de70d4fc4e5e46e9fa6da390a1298fca6fe079552f6707da8a3410ca2a1b8e66c832032feadc2f0e74f488e40431d343b8abd88cc50629c76d80e79365fe8b12775fa873f3b0d6b559a41844534a73599bf511fa16415ccdfd83a1958d79fa24881507e91dcf0bd67f3e1ad09af1027358cdb303
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93192);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/27");

  script_cve_id("CVE-2016-1478");
  script_bugtraq_id(92317);
  script_osvdb_id(142571);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva35619");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160804-wedge");

  script_name(english:"Cisco IOS NTP Packet Handling Remote DoS (cisco-sa-20160804-wedge)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability due to insufficient checks on clearing invalid
Network Time Protocol (NTP) packets from the interface queue. An
unauthenticated, remote attacker can exploit this to cause an
interface wedge, resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160804-wedge
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57eccdac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva35619.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '15.5(3)S3' ) flag++;
if ( ver == '15.6(1)S2' ) flag++;
if ( ver == '15.6(2)S1' ) flag++;
if ( ver == '15.6(2)T1' ) flag++;

# NTP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");

  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
    if (
      "%NTP is not enabled." >< buf &&
      "system poll" >!< buf &&
      "Clock is" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCva35619",
    cmds     : make_list("show ntp status")
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
