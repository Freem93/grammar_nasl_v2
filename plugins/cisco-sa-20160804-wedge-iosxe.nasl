#TRUSTED a0994a5e331e794a7c0ea9ed1fdc9ef1e6e0b8425f3a0647e56cf7737f9b64fd73c7ca2c250ceb4ffc18bc5040586145bd7b4bdd3d69053f5653fb69f910fdf931c0bc6211d07b640e0be4ae884a1159b68e585685646334561db511c3e9be6e8a2bfb87537c9684d41771bf081c435ab1ed3f9b96e687cc052d5e7520f34217b3eea3c4a1cbd348c6bc2cf010dd90d38d1954a6c3c9cf69bcde9f1af12b102c87bf5fd18b0615c5c10ceb8d2b5c54beebc37773b25921ef9df880fb4686eab97c9e4f21c9839b6c445ddd3002c3e8f73ff1538faab8c79aa547ee0de39405a9873343ff5e55fcd60a9a7282949d15c6988a8b6c8ee9fd62f5e9bc140799d0418126815582730f93c3884e7687d271392012cc9450fafcb8ca1de0222aed39a1f9a5d6a9e53fed1b4fafcfe80de59054c7a4cb3651989b64e921cfa25ae9ad226f06d82c8553abda1b9b6dd9fd1bf46e3d7dbc597985d070af4b9a0785a294f47f990ff1ab42477f96cead2f4226091c5823e9ea364ed29eb6e7a13fe82a744bbc1dd3a28756a2c16a0f8efabb6f45a4ef482b1268ebfcfb64ee2014502e4048436cc3777ae1ffded96454583a3ea427bc3a43a23233918aba36053704a91ec3e064aeea0614efd68483f4046e540fb415ea735a8731be9f27ab21b6cdff2f8dbbc3a490d7ff89f17ee94bf207f83f33f7ea1fabec8134d2ea426f6512d7c767
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93193);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/27");

  script_cve_id("CVE-2016-1478");
  script_bugtraq_id(92317);
  script_osvdb_id(142571);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva35619");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160804-wedge");

  script_name(english:"Cisco IOS XE NTP Packet Handling Remote DoS (cisco-sa-20160804-wedge)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by a denial
of service vulnerability due to insufficient checks on clearing
invalid Network Time Protocol (NTP) packets from the interface queue.
An unauthenticated, remote attacker can exploit this to cause an
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

# Check for vuln version
if ( ver == '3.16.3S' ) flag++;
if ( ver == '3.17.2S' ) flag++;
if ( ver == '3.18.1S' ) flag++;
#if ( ver == '?.?.?' ) flag++; # 15.6(2)T1 IOS == ? IOS XE

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
