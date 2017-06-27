#TRUSTED 0a8829d1aa43558b5869503f75f545acc3911c6c7c0307b1a2cc50f08fef20c6a388838c81a94b2b6e9258ad1fb3682907b31d735034e53ca4b891c28b54cc5f56473323e642e3037687233fd1d5a4fee7d3dc1bcdeb16653105f7ca2fcf2b95581e85fb793f7e042a6566c4ba5779bcfd9602b6036f9e0493ac9eb8fe8618bf7e2d7945502905fd389140aedb42cf6bb8b2afca6c69bcb563db9e67e1be9818a668eae8efc1b3c1ffdc404fc46220275b9131e8d98788c27d1d0f923fbea707ee7ef8358e7d85b9b0442de39d33d70c562dbb9de2f867061553ad79d8df67a5dfd3b4764c67675d3dae9d9a264f1fce6f52e542ff2593306cb676d7cccba5eea461164477fa25eea4969fb5acd5b0c97302bd7d1ee3bbaa19ac088b8b2825a93bb96d40357b406075c334b3f5cec38b1280996a745e4094923fe5b21e2e3870a92faeccafda3c7d159f3e9625e1600a787be707feaea57798f68f9b2b05d6c6d494c609c72b3c6d4128636f4622539d5917ec53e3034ff2156146c449987aee8c94402e9d1a11eb7a42847350e1b8ecd08b61dbdee91dc3715e644d2a31b54ab437ab023548082b06612c1499bac87bafe207efecc1e0a3ba657b725e0e5dbe64451e16581408df296cd306479a7d181896212ff22e49b59b8bb432191bbf84624c55a6a95cb9dd56a56942317db23187df69f1b33b7530d1c2f20d00925790
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87821);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/27");

  script_cve_id("CVE-2015-6429");
  script_bugtraq_id(79745);
  script_osvdb_id(132024);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw08236");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151218-ios");

  script_name(english:"Cisco IOS XE Software IKEv1 State Machine DoS (CSCuw08236)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Internet Key Exchange version 1 (IKEv1) subsystem
due to insufficient condition checks in the IKEv1 state machine. An
unauthenticated, remote attacker can exploit this vulnerability, by
sending a spoofed, specific IKEv1 packet to an endpoint of an IPsec
tunnel, to tear down IPsec tunnels that terminate on the endpoint,
resulting in a partial denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151218-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b10e25c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw08236");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20151218-ios.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

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


# 3.15.2S / 3.16.1S / 3.17.1S Labeled not-vuln in SA
if (
  # CVRF IOS XE unmapped
  ver == "3.15.0S" ||
  ver == "3.15.1S" ||
  ver == "3.17.0S" ||
  ver == "3.16.0S" ||

  # CVRF IOS XE mapped (via cisco_ios_xe_version.nasl)
  ver == "3.13.0S" || # IOS 15.4(3)S
  ver == "3.14.0S"    # IOS 15.5(1)S
)
{
  flag++;
}

cmds = make_list();
# Check that IKEv1 or ISAKMP is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500)\s";

  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:pat, string:buf)
    )
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

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s500\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s848\s", string:buf) ||
      preg(multiline:TRUE, pattern:"^17(\(v6\))?\s+--listen--.*\s4500\s", string:buf)
    )
    {
      flag = 1;
      cmds = make_list(cmds, "show udp");
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : ver,
    bug_id   : "CSCuw08236",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
