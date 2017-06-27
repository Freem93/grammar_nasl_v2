#TRUSTED 24f3f8fbade1f73f99fb0a5af117d076b9c24edfd335e57d47b8876b3ed77572597fa94cc5227a52e8a7eee56f416a1294481a3fb622e8e4c697ca1065685194d96314ec910cd456f89fa9cd1ebbe2cd0e04eff1fcef6793faff9b8b009a588bc3bf640b8251cd54ba81abbd761084f33fd4ba623d5ea29c8853e38464c3d0b15ffcce668c5ac4c126b9b953d2c57e38259dde88192fdd4c6d5a4ea273e3467b3576634cf3e4e996755e3f7ff451d17ceca0032ff82c0c235c7e440591431fe2849fdb9e39d7c4585065880b188a9edd628c3a00cdf57f171a9dcec804093189b776d64c8a955509bb780910c9a21970867c1b92ff281a9ad91c4e461c4921dbd77b688aeee0070b4529efa3d617f7e30c3a6e6bb85bf60e32d3e92b45932d5fb41d29922feee9341ab4ede139e9e0d3cd9f6bec721b68dd56b243b0ecf99bc991c9b88bf015e4719bb546461386ae2f6b3c3c0d3a33e2cf17ebb88b1146a6c72dceb2960643db829082c96697ba06d0844cb2976a59a6f6d4b65796e55b4e9252b4fbaa1ff1e029130c7f69c24047fc8708b34e99d9568e9bfd46d4e5f34211ff1c59d28706673cd648dde9deb3cf0170dda65d56b0780b0921659c702608ef1f1493bccd916c8e207d3445a8160aa78dfee31427429748b71be946da7bb88e6f5077fb93c667e85d710752136f65e0aaf06d5716adb18e603cf4b99fb04f91
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94252);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/24");

  script_cve_id("CVE-2016-6391");
  script_bugtraq_id(93197);
  script_osvdb_id(144889);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur69036");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-cip");

  script_name(english:"Cisco IOS Software CIP Request DoS (cisco-sa-20160928-cip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a denial of
service vulnerability in the Common Industrial Protocol (CIP) feature
due to improper processing of unusual but valid CIP requests. An
unauthenticated, remote attacker can exploit this, via specially
crafted CIP requests, to cause the switch to stop processing traffic,
requiring a device restart to regain functionality.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-cip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce256c81");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCur69036.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/25");

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

vuln_versions = make_list(
  '15.3(3)JAB',
  '15.3(3)JB75',
  '15.2(3)EA',
  '12.2(55)SE7',
  '12.2(50)SE3',
  '15.0(2)SE6',
  '15.2(2)E',
  '15.3(3)JNP',
  '15.3(3)JA',
  '15.3(3)JAX',
  '15.3(3)JN8',
  '15.0(2)SE5',
  '15.3(3)JA5',
  '12.2(55)SE6',
  '15.3(3)JBB6',
  '12.2(46)SE',
  '12.2(50)SE2',
  '15.3(3)JB',
  '15.3(3)JBB6a',
  '12.2(50)SE',
  '15.3(3)JNC',
  '15.3(3)JN4',
  '15.3(3)JBB2',
  '15.2(2)E1',
  '12.2(55)SE',
  '15.0(2)SE',
  '12.2(44)EX1',
  '15.3(3)JA9',
  '15.3(3)JA1',
  '15.0(2)SE1',
  '15.2(1)EY',
  '15.3(3)JN7',
  '15.3(3)JBB1',
  '15.0(1)EY',
  '15.3(3)JA8',
  '12.2(50)SE4',
  '15.0(2)EB',
  '15.3(3)JA7',
  '12.2(55)SE3',
  '15.3(3)JBB4',
  '15.3(3)JA1n',
  '15.3(3)JNC1',
  '15.0(2)SE9',
  '12.2(46)SE2',
  '15.3(3)JA77',
  '15.0(2)SE4',
  '12.2(55)SE4',
  '15.3(3)JNP1',
  '15.0(2)EY1',
  '15.2(2)E4',
  '15.3(3)JC',
  '15.3(3)JBB8',
  '12.2(44)EX',
  '15.0(2)EY2',
  '15.0(2)SE2',
  '15.0(2)SE7',
  '15.3(3)JA4',
  '15.3(3)JAX1',
  '15.2(2)E2',
  '15.0(1)EY2',
  '12.2(55)SE5',
  '12.2(50)SE5',
  '15.3(3)JAX2',
  '15.0(1)EY1',
  '15.3(3)JBB5',
  '15.3(3)JA1m',
  '15.3(3)JNB1',
  '15.0(2)SE3',
  '15.3(3)JBB',
  '15.0(2)EY',
  '15.3(3)JNB',
  '15.3(3)JNB2',
  '15.3(3)JN3',
  '12.2(50)SE1',
  '15.0(2)EY3',
  '12.2(55)SE9',
  '12.2(55)SE10',
  '12.2(58)SE2',
  '15.3(3)JAA',
  '15.3(3)JNB3',
  '12.2(46)SE1',
  '12.2(52)SE',
  '12.2(55)SE8',
  '15.3(3)JBB50',
  '12.2(52)SE1'
);

# Check for vuln version
foreach version (vuln_versions)
{
  if (version == ver)
  {
    flag++;
    break;
  }
}

# Check that cip is enabled                                           
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show run | include cip");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"cip enable", string:buf))
      flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override++;
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCur69036',
    cmds     : make_list('show running-config', 'show run | include cip')
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS software", ver);
