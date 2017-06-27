#TRUSTED 1f8039edf82f9880d27492ffca9d1875e96c61886fdb361cccf878a007a266843e842bcbdd0d00b7cc2529c2164e6354828351e80184c6848d61fe7856820027de15a7e7d5a49722166a7019d4f0c2ba28e9970c7105e88db434db6ca51989564b587cd09f77901a533285209a53dd2f9b7dc03d0aae823a4b425fdfd5ee27d07505538384cfa83e456c769e39e5252fd736a8b24b0e8557d375b664beafe14fad4c7d9c9062babcc68f6551aef4f553cb3bd273f7a7246ed636b8bb044057a7187b79acaa5d58e32be94aad63b6cdbf3e026a5c630b69d9f6373d7a41ec4e3364f82b81bb04170e6bd174a04445fc44de9f4840d9c740366fcaa03e0c95e87b55a306171733c915248510e4214b4116081ff1a678f29b319240b6234c5b2af5d0cd3e9b25751b7ae3d2467c523ebbb7a47697f7d144fd878c511941dbe50c1ecb40d1db3c4286e10646ee47bd1877654b8c5159aa12b37391494a9a52db14e8fbd0c7e2ae0e05b0907cd2b76d73ebe0dee057a89a891a38fa1e825b68d9db62949afd4f129873f6522fec519159f76b16aac21fa6dd9b5dfabc2fde75fbd9e726a4438f4890499809d25f2e3df4bcfe0e701d6ebf8720cf583c03d5bd610dcb46ba0976de5d2074e6618e9f32834ab19e7d8a3633923c7a616bb3f9a39dfda5b02ceaa907ff52efe15576595d2d7e36f4d8799f24e8ab2ac037f6912a07740e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93738);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/12/02");

  script_cve_id("CVE-2016-6415");
  script_bugtraq_id(93003);
  script_osvdb_id(144404);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb29204");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160916-ikev1");

  script_name(english:"Cisco IOS XR IKEv1 Packet Handling Remote Information Disclosure (cisco-sa-20160916-ikev1) (BENIGNCERTAIN)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XR software running on the remote device is affected by an
information disclosure vulnerability, known as BENIGNCERTAIN, in the
Internet Key Exchange version 1 (IKEv1) subsystem due to improper
handling of IKEv1 security negotiation requests. An unauthenticated,
remote attacker can exploit this issue, via a specially crafted IKEv1
packet, to disclose memory contents, resulting in the disclosure of
confidential information including credentials and configuration
settings.

BENIGNCERTAIN is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7f2c76c");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"see_also", value:"https://blogs.cisco.com/security/shadow-brokers");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb29204.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

flag     = FALSE;
override = FALSE;

if (
  version =~ "^4\.3\."
  ||
  version =~ "^5\.0\."
  ||
  version =~ "^5\.1\."
  ||
  version =~ "^5\.2\."
)
  flag = TRUE;

# Check that IKEv1 config or IKEv1 is running
cmd_list = make_list();
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv1 config
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if (
      "crypto gdoi" >< buf
      ||
      "crypto map" >< buf
      ||
      "tunnel protection ipsec" >< buf
    )
    {
      flag = 1;
      cmd_list = make_list("show running-config");
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv1 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500|4848)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        )
        {
          cmd_list = make_list(cmd_list, "show ip sockets");
          flag = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
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
          cmd_list = make_list(cmd_list, "show udp");
        }
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : "CSCvb29204",
    cmds     : cmd_list
  );
}
else audit(AUDIT_HOST_NOT, "affected");
