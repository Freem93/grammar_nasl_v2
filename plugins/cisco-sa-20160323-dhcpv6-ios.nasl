#TRUSTED 732943f85a4aaf7081339deb0d400ff130f8db8f80ae83d3b9bd4f9da56b835aff65fc7253817ca425ce906cb24f5c502c9dab292156d6019fb98ffeba5b866bfb6a8a952aed4c9082f3b0a4fce1046e19410a92541110b213855b59f72ce1978ae42f38b1ad54a510fe7157bc38229ab1f92d6d0b2828827e136b850825ef72d62bf0031f2f1bbcb480abbec33e2121ff1da75aba48d36c99ba72517e7fd61d56dc756f9ee14881766906804c333c81a34a3efa54edad827b85c7fe79ac63303c005644b6d35d4b604cb04467e6d5c1313e2df00e5f6cec349ba0fa9b4b73ce5e25a0fc5479c21a758b35327d13fde24555931c7c7fe74fe10f71885b2e4f006f7aff8a0abcb4556b8b99dec20a8b52e0bda5a718b8db63fa30075f4b580405f987547b55655e37d864e11d9cac63b712a01c866638d441361cc9c92f0548ec9f4506c727f7049ea74c9f0d0b847d24d3938d8cff4288d6150e80b590b7ee516f09a5d86d3df186f8bf385f9d96c631b1775922d578c5698d4e2052849aea0e11b4eed32033a7c3c61d9c67889031daa2391ed4d7fa44dd5b2ffdd3f339efcb1362b69596a04cc92399ff4a184fafeb09f52a2f043026ab2a393d6c50b6d11e71fe4cd98348c7f2979f74e781f10b3bf04b54c323e7248e22ded3d965d8bc45a036f8b14b93e839188e597b0d54eb67b106df009a4680360bd50cd4016a7e52
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90353);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/06");

  script_cve_id("CVE-2016-1348");
  script_osvdb_id(136246);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus55821");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-dhcpv6");

  script_name(english:"Cisco IOS DHCPv6 Relay Message Handling DoS (cisco-sa-20160323-dhcpv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the DHCPv6 Relay feature due to improper validation of DHCPv6 relay
messages. An unauthenticated, remote attacker can exploit this issue,
via a crafted DHCPv6 relay message, to cause the device to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7cde0b5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus55821.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

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

# Check for vuln version
if ( ver == '15.0(1)SY3' ) flag++;
if ( ver == '15.0(1)SY4' ) flag++;
if ( ver == '15.0(1)SY5' ) flag++;
if ( ver == '15.0(1)SY6' ) flag++;
if ( ver == '15.0(1)SY7' ) flag++;
if ( ver == '15.0(1)SY7a' ) flag++;
if ( ver == '15.0(1)SY8' ) flag++;
if ( ver == '15.0(1)SY9' ) flag++;
if ( ver == '15.1(1)SY1' ) flag++;
if ( ver == '15.1(1)SY2' ) flag++;
if ( ver == '15.1(1)SY3' ) flag++;
if ( ver == '15.1(1)SY4' ) flag++;
if ( ver == '15.1(1)SY5' ) flag++;
if ( ver == '15.1(1)SY6' ) flag++;
if ( ver == '15.1(2)SY' ) flag++;
if ( ver == '15.1(2)SY1' ) flag++;
if ( ver == '15.1(2)SY2' ) flag++;
if ( ver == '15.1(2)SY3' ) flag++;
if ( ver == '15.1(2)SY4' ) flag++;
if ( ver == '15.1(2)SY4a' ) flag++;
if ( ver == '15.1(2)SY5' ) flag++;
if ( ver == '15.1(2)SY6' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(2)E1' ) flag++;
if ( ver == '15.2(2)E2' ) flag++;
if ( ver == '15.2(2)E3' ) flag++;
if ( ver == '15.2(2a)E1' ) flag++;
if ( ver == '15.2(2a)E2' ) flag++;
if ( ver == '15.2(3)E' ) flag++;
if ( ver == '15.2(3)E1' ) flag++;
if ( ver == '15.2(3)E2' ) flag++;
if ( ver == '15.2(3a)E' ) flag++;
if ( ver == '15.2(3m)E2' ) flag++;
if ( ver == '15.2(3m)E3' ) flag++;
if ( ver == '15.2(4)E' ) flag++;
if ( ver == '15.2(2)EB' ) flag++;
if ( ver == '15.2(2)EB1' ) flag++;
if ( ver == '15.2(1)EY' ) flag++;
if ( ver == '15.2(2)EA1' ) flag++;
if ( ver == '15.2(2)EA2' ) flag++;
if ( ver == '15.2(3)EA' ) flag++;
if ( ver == '15.2(4)EA' ) flag++;
if ( ver == '15.2(1)S' ) flag++;
if ( ver == '15.2(1)S1' ) flag++;
if ( ver == '15.2(1)S2' ) flag++;
if ( ver == '15.2(2)S' ) flag++;
if ( ver == '15.2(2)S0a' ) flag++;
if ( ver == '15.2(2)S0c' ) flag++;
if ( ver == '15.2(2)S1' ) flag++;
if ( ver == '15.2(2)S2' ) flag++;
if ( ver == '15.2(4)S' ) flag++;
if ( ver == '15.2(4)S1' ) flag++;
if ( ver == '15.2(4)S2' ) flag++;
if ( ver == '15.2(4)S3' ) flag++;
if ( ver == '15.2(4)S3a' ) flag++;
if ( ver == '15.2(4)S4' ) flag++;
if ( ver == '15.2(4)S4a' ) flag++;
if ( ver == '15.2(4)S5' ) flag++;
if ( ver == '15.2(4)S6' ) flag++;
if ( ver == '15.2(4)S7' ) flag++;
if ( ver == '15.2(2)SNG' ) flag++;
if ( ver == '15.2(2)SNH1' ) flag++;
if ( ver == '15.2(2)SNI' ) flag++;
if ( ver == '15.2(1)SY' ) flag++;
if ( ver == '15.2(1)SY0a' ) flag++;
if ( ver == '15.2(1)SY1' ) flag++;
if ( ver == '15.2(1)SY1a' ) flag++;
if ( ver == '15.2(2)SY' ) flag++;
if ( ver == '15.3(1)S' ) flag++;
if ( ver == '15.3(1)S1' ) flag++;
if ( ver == '15.3(1)S2' ) flag++;
if ( ver == '15.3(2)S' ) flag++;
if ( ver == '15.3(2)S0a' ) flag++;
if ( ver == '15.3(2)S1' ) flag++;
if ( ver == '15.3(2)S2' ) flag++;
if ( ver == '15.3(3)S' ) flag++;
if ( ver == '15.3(3)S1' ) flag++;
if ( ver == '15.3(3)S1a' ) flag++;
if ( ver == '15.3(3)S2' ) flag++;
if ( ver == '15.3(3)S3' ) flag++;
if ( ver == '15.3(3)S4' ) flag++;
if ( ver == '15.3(3)S5' ) flag++;
if ( ver == '15.3(3)S6' ) flag++;
if ( ver == '15.4(1)S' ) flag++;
if ( ver == '15.4(1)S1' ) flag++;
if ( ver == '15.4(1)S2' ) flag++;
if ( ver == '15.4(1)S3' ) flag++;
if ( ver == '15.4(1)S4' ) flag++;
if ( ver == '15.4(2)S' ) flag++;
if ( ver == '15.4(2)S1' ) flag++;
if ( ver == '15.4(2)S2' ) flag++;
if ( ver == '15.4(2)S3' ) flag++;
if ( ver == '15.4(2)S4' ) flag++;
if ( ver == '15.4(3)S' ) flag++;
if ( ver == '15.4(3)S1' ) flag++;
if ( ver == '15.4(3)S2' ) flag++;
if ( ver == '15.4(3)S3' ) flag++;
if ( ver == '15.4(3)S4' ) flag++;
if ( ver == '15.5(1)S' ) flag++;
if ( ver == '15.5(1)S1' ) flag++;
if ( ver == '15.5(1)S2' ) flag++;
if ( ver == '15.5(1)S3' ) flag++;
if ( ver == '15.5(2)S' ) flag++;
if ( ver == '15.5(2)S1' ) flag++;
if ( ver == '15.5(2)S2' ) flag++;
if ( ver == '15.5(3)S' ) flag++;
if ( ver == '15.5(3)S0a' ) flag++;
if ( ver == '15.5(3)S1' ) flag++;
if ( ver == '15.5(3)S1a' ) flag++;
if ( ver == '15.5(3)SN' ) flag++;

# Check for DHCPv6 Relay
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    if ("is in relay mode" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCus55821' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
