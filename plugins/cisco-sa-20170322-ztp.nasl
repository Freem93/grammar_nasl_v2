#TRUSTED 87335c8315d403c9bbddf0c9c2a6cddbba7f1a081bac14f616af7c478996cff3a6c1ea161505617d676fc028411be903b06c5e1c9b8995db33784e2132456b1e3a0711b624e06fc96c2024c7104b60e40eddcea822339ebbda54498375f0566a2a992890c6f16c208b988cbafc9b0867007a32f6c4661430865f10f92c73bfdaea934bd04d98d7d58b6605f06490135f9b2b5020eb100c37d13272b94f6f0769325456e9cc4d2dbc6b3729bfe7a9f7ea6e7922cbefe1d2d3253e07089542d90d5042fb68b28ca02850ae59533ff295a39e971c3ec3788dd605709fade3bb0cfdf1e20e26d9c079ed8207031a5461059afa25893c03a5f94c3d4866c4258aebfb8d7133cad8d35fa3f29944ff944cb106064e92c68bc7d5f23f8e538e5352e54f1608e54f1332eba72a4473408326c8cec2668ba11d5d45e066b7a7dd452c86be2cfbe7b2bf3a4ca2ef05216a31c80bce870d95c99d078dc13dc2580210561377e2d8c3d437d560152e0cae92cbabfc6086c6b5a6bc15c65423d50137c0404155bf61f12637173f56182976f77880565d7251d41ebd3aa5add625f594c4087204adaaea0d3ee1c4f17deda9c97bbc1e530b48c34e1846173bd6ab4fd62826dd980496da30471378941ddf313222c67e7217c014bb0c2854dba5abd1a87eef8f1e4740b7f5020f873e9ea70700052c46dba841138199afc582293960cea9012f17
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99033);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3859");
  script_bugtraq_id(97008);
  script_osvdb_id(154194);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy56385");
  script_xref(name:"IAVA", value:"2017-A-0083");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-ztp");

  script_name(english:"Cisco IOS XE for Cisco ASR 920 Series Routers Zero Touch Provisioning DoS (cisco-sa-20170322-ztp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote Cisco ASR 920 Series device is affected by a
denial of service vulnerability due to a format string flaw when
processing DHCP packets for Zero Touch Provisioning. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted DHCP packet, to cause the device to reload.

Note that for this vulnerability to be exploited, the device must be
configured to listen on the DHCP server port. By default, the device
does not listen on this port.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-ztp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?339c4225");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy56385");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy56385");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (model !~ "^ASR920$")
  audit(AUDIT_HOST_NOT, "an affected model");

flag = 0;
override = 0;

if (
  ver == "3.13.4S" ||
  ver == "3.13.5S" ||
  ver == "3.13.5aS" ||
  ver == "3.13.6S" ||
  ver == "3.13.6aS" ||
  ver == "3.14.3S" ||
  ver == "3.14.4S" ||
  ver == "3.15.2S" ||
  ver == "3.15.3S" ||
  ver == "3.15.4S" ||
  ver == "3.16.0S" ||
  ver == "3.16.1S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.2S" ||
  ver == "3.16.2aS" ||
  ver == "3.16.0cS" ||
  ver == "3.16.3S" ||
  ver == "3.16.2bS" ||
  ver == "3.16.3aS" ||
  ver == "3.17.0S" ||
  ver == "3.17.1S" ||
  ver == "3.17.2S " ||
  ver == "3.17.1aS" ||
  ver == "3.18.0aS" ||
  ver == "3.18.0S" ||
  ver == "3.18.1S" ||
  ver == "3.18.2S" ||
  ver == "3.18.3vS" ||
  ver == "3.18.0SP" ||
  ver == "3.18.1SP" ||
  ver == "3.18.1aSP" ||
  ver == "3.18.1bSP" ||
  ver == "3.18.1cSP"
)
{
  flag++;
}

cmds = make_list();
# Confirm whether a device is listening on the DHCP server port
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  pat = "^(Proto|\d+)?.*17(\(v6\))?\s+(--listen--|\d+.\d+.\d+.\d+).*\s67\s";

  buf = cisco_command_kb_item("Host/Cisco/Config/show ip sockets", "show ip sockets");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:pat, string:buf))
    {
      cmds = make_list(cmds, "show ip sockets");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuy56385",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
