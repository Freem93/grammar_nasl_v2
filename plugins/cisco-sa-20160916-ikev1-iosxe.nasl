#TRUSTED 1cfd295acec955d4e8ff682c41b9d82224e53174a17322e824903a37fc8298d83cabe223a50c8ae88911218966125c615167241b518936e2078977a765cbe4e9d7fc5148c2e122e65222b5fcdfcd9073ea1dadd956cbecca6c9f2842e02036f5c36d6fdc55e4b1cc25219119f82237b065c82bf6729b5d36360ceead9d864ed99ef641b1dba730769802bfc921645dad105bc924d67a317a72b22da1b8d1219e670d170888d8533636c143a8f602caeb59e2521bb336081718f520e3285f371785b8afe311c21bba9ae20bf0203e752604b7ba55a3ac3228a279aa9b1e306c7f1bcb7b194da4b9bb8bbebf612516813012925536dc246bb76ce6c58f9b8e352b179430f36f5740295c3d96799cd4fa87f561c6230c80d7c0f1b11916b18697f5ff64d9ec57d99ba12e5c1883a4c240fc151537cdb635107bf0fbd3d403db42656eab0821bfabf7f2848cbc016d1d0e6193a0ec04659b0d5dec72e0d39d6211f47332be4b9d9ccd90138c5fd5dd6530aa4ac56ebd711ae5d5f328b1a33197031456343781e6f27069d2234ebfda1ee2444f5357c72215b45ea072ba1480b26428e28ec105bafe41a0e36758190d4ec7c90dd74539401c900c40d3c4bf6b246fe0209ed4502355855d3185cd17dae6dc021e04fc6515fc7ed0514d8b86ae24b5a9c07030dd6fa944d1e821c54a3ab543f6fc2952439088445613a82f27e6c72b51
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93737);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/12/02");

  script_cve_id("CVE-2016-6415");
  script_bugtraq_id(93003);
  script_osvdb_id(144404);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb29204");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160916-ikev1");

  script_name(english:"Cisco IOS XE IKEv1 Packet Handling Remote Information Disclosure (cisco-sa-20160916-ikev1) (BENIGNCERTAIN)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by an
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

# Check for vuln version
if ( ver == "3.1.0S" ) flag++;
else if ( ver == "3.1.1S" ) flag++;
else if ( ver == "3.1.2S" ) flag++;
else if ( ver == "3.1.3aS" ) flag++;
else if ( ver == "3.1.4aS" ) flag++;
else if ( ver == "3.1.4S" ) flag++;
else if ( ver == "3.2.1S" ) flag++;
else if ( ver == "3.2.2S" ) flag++;
else if ( ver == "3.3.0S" ) flag++;
else if ( ver == "3.3.0SG" ) flag++;
else if ( ver == "3.3.1S" ) flag++;
else if ( ver == "3.3.1SG" ) flag++;
else if ( ver == "3.3.2S" ) flag++;
else if ( ver == "3.3.2SG" ) flag++;
else if ( ver == "3.4.0aS" ) flag++;
else if ( ver == "3.4.0S" ) flag++;
else if ( ver == "3.4.0SG" ) flag++;
else if ( ver == "3.4.1S" ) flag++;
else if ( ver == "3.4.1SG" ) flag++;
else if ( ver == "3.4.2S" ) flag++;
else if ( ver == "3.4.2SG" ) flag++;
else if ( ver == "3.4.3S" ) flag++;
else if ( ver == "3.4.3SG" ) flag++;
else if ( ver == "3.4.4S" ) flag++;
else if ( ver == "3.4.4SG" ) flag++;
else if ( ver == "3.4.5S" ) flag++;
else if ( ver == "3.4.5SG" ) flag++;
else if ( ver == "3.4.6S" ) flag++;
else if ( ver == "3.4.6SG" ) flag++;
else if ( ver == "3.4.7SG" ) flag++;
else if ( ver == "3.5.0E" ) flag++;
else if ( ver == "3.5.0S" ) flag++;
else if ( ver == "3.5.1E" ) flag++;
else if ( ver == "3.5.1S" ) flag++;
else if ( ver == "3.5.2E" ) flag++;
else if ( ver == "3.5.2S" ) flag++;
else if ( ver == "3.5.3E" ) flag++;
else if ( ver == "3.6.0E" ) flag++;
else if ( ver == "3.6.0S" ) flag++;
else if ( ver == "3.6.1E" ) flag++;
else if ( ver == "3.6.1S" ) flag++;
else if ( ver == "3.6.2aE" ) flag++;
else if ( ver == "3.6.2E" ) flag++;
else if ( ver == "3.6.2S" ) flag++;
else if ( ver == "3.6.4E" ) flag++;
else if ( ver == "3.6.5E" ) flag++;
else if ( ver == "3.7.0E" ) flag++;
else if ( ver == "3.7.0S" ) flag++;
else if ( ver == "3.7.1E" ) flag++;
else if ( ver == "3.7.1S" ) flag++;
else if ( ver == "3.7.2E" ) flag++;
else if ( ver == "3.7.2S" ) flag++;
else if ( ver == "3.7.2tS" ) flag++;
else if ( ver == "3.7.3E" ) flag++;
else if ( ver == "3.7.3S" ) flag++;
else if ( ver == "3.7.4aS" ) flag++;
else if ( ver == "3.7.4S" ) flag++;
else if ( ver == "3.7.5E" ) flag++;
else if ( ver == "3.7.5S" ) flag++;
else if ( ver == "3.7.6S" ) flag++;
else if ( ver == "3.7.7S" ) flag++;
else if ( ver == "3.8.0E" ) flag++;
else if ( ver == "3.8.0S" ) flag++;
else if ( ver == "3.8.1E" ) flag++;
else if ( ver == "3.8.1S" ) flag++;
else if ( ver == "3.8.2E" ) flag++;
else if ( ver == "3.8.2S" ) flag++;
else if ( ver == "3.9.0aS" ) flag++;
else if ( ver == "3.9.0E" ) flag++;
else if ( ver == "3.9.0S" ) flag++;
else if ( ver == "3.9.1aS" ) flag++;
else if ( ver == "3.9.1S" ) flag++;
else if ( ver == "3.9.2S" ) flag++;
else if ( ver == "3.10.0S" ) flag++;
else if ( ver == "3.10.1S" ) flag++;
else if ( ver == "3.10.1xbS" ) flag++;
else if ( ver == "3.10.2S" ) flag++;
else if ( ver == "3.10.2tS" ) flag++;
else if ( ver == "3.10.3S" ) flag++;
else if ( ver == "3.10.4S" ) flag++;
else if ( ver == "3.10.5S" ) flag++;
else if ( ver == "3.10.6S" ) flag++;
else if ( ver == "3.10.7S" ) flag++;
else if ( ver == "3.11.0S" ) flag++;
else if ( ver == "3.11.1S" ) flag++;
else if ( ver == "3.11.2S" ) flag++;
else if ( ver == "3.11.3S" ) flag++;
else if ( ver == "3.11.4S" ) flag++;
else if ( ver == "3.12.0aS" ) flag++;
else if ( ver == "3.12.0S" ) flag++;
else if ( ver == "3.12.1S" ) flag++;
else if ( ver == "3.12.2S" ) flag++;
else if ( ver == "3.12.3S" ) flag++;
else if ( ver == "3.12.4S" ) flag++;
else if ( ver == "3.13.0aS" ) flag++;
else if ( ver == "3.13.0S" ) flag++;
else if ( ver == "3.13.1S" ) flag++;
else if ( ver == "3.13.2aS" ) flag++;
else if ( ver == "3.13.2S" ) flag++;
else if ( ver == "3.13.3S" ) flag++;
else if ( ver == "3.13.4S" ) flag++;
else if ( ver == "3.13.5aS" ) flag++;
else if ( ver == "3.13.5S" ) flag++;
else if ( ver == "3.13.6aS" ) flag++;
else if ( ver == "3.13.6S" ) flag++;
else if ( ver == "3.14.0S" ) flag++;
else if ( ver == "3.14.1S" ) flag++;
else if ( ver == "3.14.2S" ) flag++;
else if ( ver == "3.14.3S" ) flag++;
else if ( ver == "3.14.4S" ) flag++;
else if ( ver == "3.15.0S" ) flag++;
else if ( ver == "3.15.1cS" ) flag++;
else if ( ver == "3.15.1S" ) flag++;
else if ( ver == "3.15.2S" ) flag++;
else if ( ver == "3.15.3S" ) flag++;
else if ( ver == "3.16.0cS" ) flag++;
else if ( ver == "3.16.0S" ) flag++;
else if ( ver == "3.16.1aS" ) flag++;
else if ( ver == "3.16.1S" ) flag++;
else if ( ver == "3.16.2aS" ) flag++;
else if ( ver == "3.16.2S" ) flag++;
else if ( ver == "3.17.0S" ) flag++;
else if ( ver == "3.17.1S" ) flag++;
else if ( ver == "3.17.2S" ) flag++;
else if ( ver == "3.18.0S" ) flag++;
else if ( ver == "3.18.1S" ) flag++;
else if ( ver == "3.18.2S" ) flag++;

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
          flag = 1;
          cmd_list = make_list(cmd_list, "show ip sockets");
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
    version  : ver,
    bug_id   : 'CSCvb29204',
    cmds     : cmd_list
  );
}
else audit(AUDIT_HOST_NOT, "affected");
