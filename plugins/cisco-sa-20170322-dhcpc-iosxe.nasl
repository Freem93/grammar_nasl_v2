#TRUSTED 333a28940393405bf7bbaaaf32209c187863ea0c2ee90946cf317c64457d5d7c031de28d112042119882481be538e59c18c75a3cf83fa0f900e5168fcc8040fc27b0a1d41cf195fa96b92131dcc2b8de2a2c129a0e3b0103e2003e121593e114548eae5779f4c81a170f74ef7981e4372e8cfed13c92c1318a17c59c0efa6ad1a1b62fe85654b2e5fc2db01dcfe8f770d3d2978c9570b5032c9c799e6336d9c86674186c3c9c94b71b2489016436e20db7ad06358f95a855e98801e6d975304728248e94e1ecfa50696317708be0ffd18c1aa576eba0c39b186e3e531512c84bbd3a94a083775b4d86152f073fda4843b60e95e0c399a23dedcbef96d57685a33245adfa455a593f24de883ea6a84a413ef5c3d3ae14170ebdccc0c0a368621a64dad6b5cfb92798746d4f183a5a58933186d385bfe98dd7708aa1114bbcd5b6b9e7920d0cbc92b3de1a188bc69bc9c175fbceb8b3817a557bc0bd3b29e25cfa956ea2c67afc125e3ea04504787ff0a504f95596cdf8f193100dba5424d67b061ce60720e57b4afe42da5e6725a33a683db0bd83720c81abddad2c20e10efc30be1fed23a4770d6c41b4ac33aa474ba3d17fbb6dad7271c1d1a8fbedf9c49f7f325931750f40c841e20ebe82b6a27d3a50844001beaa2ab8fd96ec2f827107e18e8d4f012740405596c8e24d18c936f50d071b004d84190293dce6fd3a2ea108
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99027);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3864");
  script_bugtraq_id(97012);
  script_osvdb_id(154190);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu43892");
  script_xref(name:"IAVA", value:"2017-A-0083");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-dhcpc");

  script_name(english:"Cisco IOS XE DHCP Client DoS (cisco-sa-20170322-dhcpc)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the DHCP client implementation when parsing DHCP
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted DHCP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-dhcpc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d54a2ce");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu43892");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu43892.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

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

flag = 0;

if (
  ver == '3.3.0SE' ||
  ver == '3.3.0XO' ||
  ver == '3.3.1SE' ||
  ver == '3.3.1XO' ||
  ver == '3.3.2SE' ||
  ver == '3.3.2XO' ||
  ver == '3.3.3SE' ||
  ver == '3.3.4SE' ||
  ver == '3.3.5SE' ||
  ver == '3.5.0E' ||
  ver == '3.5.1E' ||
  ver == '3.5.2E' ||
  ver == '3.5.3E' ||
  ver == '3.6.0E' ||
  ver == '3.6.1E' ||
  ver == '3.6.2aE' ||
  ver == '3.6.2E' ||
  ver == '3.6.3E' ||
  ver == '3.6.4E' ||
  ver == '3.7.0E' ||
  ver == '3.7.1E' ||
  ver == '3.7.2E' ||
  ver == '3.7.3E'
)
{
  flag++;
}

cmds = make_list();
# Check that device is configured as a DHCP client
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include dhcp", "show running-config | include dhcp");
  if (check_cisco_result(buf))
  {
    if ("dhcp" >< buf)
    {
      cmds = make_list(cmds, "show running-config | include dhcp");
      # Check if device is configured as a DHCP server or DHCP relay agent
      buf2 =  cisco_command_kb_item("Host/Cisco/Config/show running-config | include helper|(ip dhcp pool)", "show running-config | include helper|(ip dhcp pool)");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"ip helper-address [0-9\.]+", string:buf2))
        {
          cmds = make_list(cmds,"show running-config | include helper|(ip dhcp pool)");
          # Check if device is configured to send DHCP Inform/Discover messages
          # If device is confiured to send DHCP Inform and Discover messages
          # then not vuln
          buf3 = cisco_command_kb_item("Host/Cisco/Config/show running-config | include (ip dhcp-client network-discovery)", "show running-config | include (ip dhcp-client network-discovery)");
          if (check_cisco_result(buf3))
          {
            if (preg(multiline:TRUE, pattern:"ip dhcp-client network-discovery informs .* discovers .*", string:buf3))
            {
              flag = 0;
            }
            else
            {
              flag = 1;
              cmds = make_list(cmds,"show running-config | include (ip dhcp-client network-discovery)");
            }
          }
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuu43892",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
