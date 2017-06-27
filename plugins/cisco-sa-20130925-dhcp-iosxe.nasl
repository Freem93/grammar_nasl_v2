#TRUSTED 87bfdb3c7d23954ab55cad004d3144e40cf9a77e4702c4eac0d4eb6ae04967375adcf250e4b0b1d5232a6328caca90bd4064692490992e4263f0c54d68ab2739b3af56e8a9164b47e247ec77cf24e1a942aca07389f1a3b5a27ea6fdf12e5b09fe93ffbf31e33c6e8f6f377f36d9ab5340b0f49e3fd7abfe057a4543d17bddeea88b32d0ae1aa50ad07db11e58f7462a21b789d3df4745f7ba4f24249b55c9b19423f5884ba6ff63622b985b2469593292426f15544a7c011cd470d1cc85843514fc0e3f52e20731d63fed35dc35601383854795e28f8e9763d9dd5198e07abe11797b132b60fbe6a7c488fad105c7febfc26857da60709f51b061c9f110f6f0ddeacec3763aa156329f022359d2d241cfa06b784ba45ac46e32cdf933a1fb363c630ecc7d949933c2b8d57d21b8015be1060ab354b6c541b778ddb55cd0a851b7961c08e8d1041584e74c34b5c995044aa793c3cf8444334927d36df779b0896c378468143958e0da242933a32a5ce49bd6a32b4d661266a3ed09e1ea1ed7c716706dfec4816b89d6b949bb9dbf89b378a1bc442dd4734d2b122913e76b4dcec492f0ddac6c60ad37397d9545ce8a88380855a47b4a3c2a2810c1812042fec7077ebf68005c718a31cda146994ceac8eb4a779dfc071c0d286030b3b318d841f7cd358b36b4a5f2791988b7079afad7ce1d2f9afcd6f1fa5e3c9be7b9c60052
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-dhcp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70315);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/07/28");

  script_cve_id("CVE-2013-5475");
  script_bugtraq_id(62644);
  script_osvdb_id(97734);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug31561");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-dhcp");

  script_name(english:"Cisco IOS XE Software DHCP Denial of Service Vulnerability (cisco-sa-20130925-dhcp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the DHCP implementation of Cisco IOS XE Software
allows an unauthenticated, remote attacker to cause a denial of
service (DoS) condition. The vulnerability occurs during the parsing
of crafted DHCP packets. An attacker can exploit this vulnerability by
sending crafted DHCP packets to an affected device that has the DHCP
server or DHCP relay feature enabled. An exploit allows the attacker
to cause a reload of an affected device. Cisco has released free
software updates that address this vulnerability. There are no
workarounds to mitigate this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-dhcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79d0979c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-dhcp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if(version =~ '^2\\.1([^0-9]|$)') flag++;
else if(version =~ '^2\\.2([^0-9]|$)') flag++;
else if(version =~ '^2\\.3([^0-9]|$)') flag++;
else if(version =~ '^2\\.4([^0-9]|$)') flag++;
else if(version =~ '^2\\.5([^0-9]|$)') flag++;
else if(version =~ '^2\\.6([^0-9]|$)') flag++;
else if(version =~ '^3\\.1(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.1(\\.[0-9]+)?SG$') flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.2(\\.[0-9]+)?SE$') && (cisco_gen_ver_compare(a:version,b:'3.2.3SE') == -1)) flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?SG$') flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?XO$') flag++;
else if(version =~ '^3\\.3(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.3(\\.[0-9]+)?SG$') flag++;
else if((version =~ '^3\\.4(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.4.6S') == -1)) flag++;
else if((version =~ '^3\\.4(\\.[0-9]+)?SG$') && (cisco_gen_ver_compare(a:version,b:'3.4.1SG') == -1)) flag++;
else if(version =~ '^3\\.5(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.6(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.7(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.7.2tS') == -1)) flag++;
else if(version =~ '^3\\.8(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.9(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
  flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_dhcp_pool", "show ip dhcp pool");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"[Aa]ddresses", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip helper-address", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip dhcp pool", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
