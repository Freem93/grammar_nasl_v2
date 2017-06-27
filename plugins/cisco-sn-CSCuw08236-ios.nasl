#TRUSTED 0fed33945131991535e20e9221d6daf087ca4b8a7994d4d9dbffc651a37d7cdb60a3f6312b767eaf525b1097575e316e96ab319831029fb7f056d280866c714d27c29ef59c171f652cc44f9476293fedfdfae9c3f0873ee6ee5f7e35e01b3c47a3b944cd3387783ec7d3ecdc9a49b07eae905d1477625cc725b6ef183170f2177cb279696d9967cc47f01df133576ef49d8cb2864a1ba61aa96444f9c6e0471c906d4a0b8dc372244f12b0713a4dcc7166765d0c0d54e6f4ad3ab46c6144b05f464ac428db0e2f984eeb6bf4aee903e9dbd2eb26a35e436bcdf949039050b77d53cde59bfeb3c2a5d8c661015d044328c3b7751953d7edd93b8565a31801d6ac7eb2613e996df376fdd1f1582df08789d0223c3dba9fec6468a4561a992df87d06b78992225781d04c38caba1637e43fa772ab8952767302b6c3c1e00ddc00da28c141530fb3efd9f0e8cb77fc03f45b22555229ce3226f350db14fc8b3f08701ed62484af6ef115a1d2ee462f92328373e797f6c3de19f16720947765a53fcf5350ba64bd61833dcac71eb6bf36c0eaf997bbf2d260872d3bc7441022ad60f58272a3d211926fec0ab7dab297a970691b0831aeddcc386707f44a05ac158f5c25c891b0ce50d5bc4a87a8f0d475b5a25d802c45010744f61cb0e9b22eab975c9b40ac8c51181aca587922cd3b4a2df1720387035d37c9398ee33412dd6e94f7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87820);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/27");

  script_cve_id("CVE-2015-6429");
  script_bugtraq_id(79745);
  script_osvdb_id(132024);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw08236");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151218-ios");

  script_name(english:"Cisco IOS Software IKEv1 State Machine DoS (CSCuw08236)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Internet Key Exchange version 1 (IKEv1) subsystem due to
insufficient condition checks in the IKEv1 state machine. An
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

# Check for vuln versions
if (
  ver == '15.4(3)S' ||
  ver == '15.5(3)M' ||
  ver == '15.5(3)M1' ||
  ver == '15.5(1)S' ||
  ver == '15.5(2)S' ||  # Maps to IOS XE 3.15.0S
  ver == '15.5(2)S1' || # Maps to IOS XE 3.15.1S
  ver == '15.5(2)S2' || # Maps to IOS XE 3.15.2S
  ver == '15.5(3)S' ||  # Maps to IOS XE 3.16.0S
  ver == '15.5(3)S1' || # Maps to IOS XE 3.16.1S
  ver == '15.5(1)T' ||
  ver == '15.5(2)T' ||
  ver == '15.6(1)S' ||  # Maps to IOS XE 3.17.0S
  ver == '15.6(1)S1' || # Maps to IOS XE 3.17.1S
  ver == '15.6(1)T0a'
) flag++;

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
      flag = 1;
      cmds = make_list(cmds, "show ip sockets");
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  if (!flag)
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
    if (check_cisco_result(buf))
    {
      if (
        preg(multiline:TRUE, pattern:pat, string:buf)
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
