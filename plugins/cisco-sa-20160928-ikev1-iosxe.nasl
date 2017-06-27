#TRUSTED b1137ff5406da5842a4f214006933172f8c17e981384a81f99e1a166a6f83768cda6b1e0f6f9a5e63f77c9fa0bdc9aafae33b493546a6c1d53a46b306ae36c7de3a1eabff64e5158d2c100621009e43a5f100b4540f82f91160ac7b79b5076ebcd1e1e86ccbb8ca31e64e99dbd7c741ebee6d41414316e665d60180ac2c92c6caa1d458e2b5569aa4e9823dbeaa546a6e7b335e4094cb1a9a755b79ebe618bf7568d6bb4973e894aa9e3f9eee515fb53998f42ca234c0994e271564867174d61e1cf34aa2ec6f22525a8dd6583cb3e2df5145f88918d04bb05be743b01ffc0f31ffe5d53341b3f4935375dc500febdecac9d1be0a4d6c079b51c7107a1b52a080d6a2eabec7483d6b502fabeaf559f9d559782c5d6f2e2f6656ab8ea406ceb4b564753a6fe7a6731348cd3898061e1802d41af6b2da181cf321525d08eac47e85c5debb4401f8990b79ac396840ad7a6aba597d65fc4691722b2ea900af43bbbb474337b25c22b8caf84b4efb88f328a9985b642e092fff9d5710f775bcbde8282518c186f6e9e6b1c83dde57ed9b99935e445aaff0b6148c2807e5dc04063f4dcf26158ce5fcc82751a1990b7eecd5d2920bc8f220fe8d783930671d36f551ba7ec3d03a90e17ab63ff9c73650f635039ecf216c0434c9c6d1b5fd6af4fb3e69f0b12c1f112b6040d4ff6edcd8c5752420c82b0ad154a55c2469cbdb96185ce
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94763);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/24");

  script_cve_id("CVE-2016-6381");
  script_bugtraq_id(93195);
  script_osvdb_id(144897);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy47382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-ios-ikev1");

  script_name(english:"Cisco IOS XE IKEv1 Fragmentation DoS (cisco-sa-20160928-ikev1)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by a denial
of service vulnerability in the Internet Key Exchange version 1
(IKEv1) subsystem due to improper handling of fragmented IKEv1
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted IKEv1 packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ios-ikev1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30c88959");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy47382. Alternatively, as a workaround, IKEv2 fragmentation can be
disabled by using the 'no crypto isakmp fragmentation' command.
However, if IKEv1 fragmentation is needed, there is no workaround that
addresses this vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/14");

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
cmds = make_list();

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
else if ( ver == "3.3.0XO" ) flag++;
else if ( ver == "3.3.1S" ) flag++;
else if ( ver == "3.3.1SG" ) flag++;
else if ( ver == "3.3.1XO" ) flag++;
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
else if ( ver == "3.6.3E" ) flag++;
else if ( ver == "3.6.4E" ) flag++;
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
else if ( ver == "3.7.5S" ) flag++;
else if ( ver == "3.7.6S" ) flag++;
else if ( ver == "3.7.7S" ) flag++;
else if ( ver == "3.8.0E" ) flag++;
else if ( ver == "3.8.0S" ) flag++;
else if ( ver == "3.8.1E" ) flag++;
else if ( ver == "3.8.1S" ) flag++;
else if ( ver == "3.8.2S" ) flag++;
else if ( ver == "3.9.0aS" ) flag++;
else if ( ver == "3.9.0S" ) flag++;
else if ( ver == "3.9.1aS" ) flag++;
else if ( ver == "3.9.1S" ) flag++;
else if ( ver == "3.9.2S" ) flag++;
else if ( ver == "3.10.0S" ) flag++;
else if ( ver == "3.10.1S" ) flag++;
else if ( ver == "3.10.1xbS" ) flag++;
else if ( ver == "3.10.2S" ) flag++;
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
else if ( ver == "3.13.5S" ) flag++;
else if ( ver == "3.14.0S" ) flag++;
else if ( ver == "3.14.1S" ) flag++;
else if ( ver == "3.14.2S" ) flag++;
else if ( ver == "3.14.3S" ) flag++;
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
else if ( ver == "3.18.0S" ) flag++;
else if ( ver == "16.1.1" ) flag++;
else if ( ver == "16.1.2" ) flag++;

if(!flag)
  audit(AUDIT_INST_VER_NOT_VULN, ver);

# Check that IKEv1 config or IKEv1 is running
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv1 config
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if ( "crypto isakmp fragmentation" >< buf )
    {
      flag = 1;
      cmds = make_list('show running-config');
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

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|4500)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:pat, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, 'show ip sockets');
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
        if (preg(multiline:TRUE, pattern:pat, string:buf))
        {
          flag = 1;
          cmds = make_list(cmds, 'show udp');
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
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCuy47382',
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
