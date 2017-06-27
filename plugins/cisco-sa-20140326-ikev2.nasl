#TRUSTED 29c67db506a2ee608de8249295e57d0d9d51883fc633f8e5312071ffef29755d6cb658d94442dce9ee75bd7cdacd18276fcf546ce29972ccfa36fb63aad1e8d2975715f5f50c8bb7984d6e8baf0f2ade9e44a1ee7764eae4e4037f6e0ee1ea7d5d986d421c9d4775c6e18dd3809a7620780810fcaa2757529887931577e7cc404d7362e236884d7c12217fdf0494bbeccd159b75d19be97b61825c468c55a93af9995e687eb14abff163eff65d7aab9cb5bf5c90a7a168d732e3c92d640213b6acec174af0b62bcd3e86426d37fc04ba38aae59078bfd8e3b51d1a283da6215396f2f270b7f1f3630d33ca83189b2ce96aa01a87d13789965becf35909e31ca5e1fab642ad7d997ed70d082055f4fa3f81b91501c4bc185e0f7940276dfdbebec151d6db8ab632d70e655ffb7578404a46ff4b8b80455123a65a4234ad28a0bf110aea32e458694b565caa6937941bc80d4d599a4c89a1f7bfaa60546890615b551087f613cfeae376b2e6b552f3a6e73f8692b94d168a2f49198c9b7f71f0aa7373c4c3a52bece2a22ff61dfa18e40c27c0da7271d4a3bbb91343b8b8281c24851ad60c903e924789687b4623daec89934c567281d0cb6ebb9847d55f3341aaa811917e25da59cca66061e7626c51c00346bf90fdcb6592446ef0e104244a4386401b24c82f099a16bd66ef50b49a95f81756dcd7ed9d42ce44f76461643e6f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73341);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2108");
  script_bugtraq_id(66471);
  script_osvdb_id(104965);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui88426");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ikev2");

  script_name(english:"Cisco IOS Software Internet Key Exchange Version 2 (IKEv2) Denial of Service (cisco-sa-20140326-ikev2)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the Internet Key Exchange Version 2 (IKEv2) module.
An unauthenticated, remote attacker could potentially exploit this
issue by sending a malformed IKEv2 packet resulting in a denial of
service.

Note that this issue only affects hosts when Internet Security
Association and Key Management Protocol (ISAKMP) is enabled.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a1b54a0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33346");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ikev2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
report = "";
cbi = "CSCui88426";
fixed_ver = "";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# 15.0ED
if (ver == '15.0(2)ED' || ver == '15.0(2)ED1')
         fixed_ver = '15.2(1)E2';
# 15.0EH
else if (ver == '15.0(2)EH')
         fixed_ver = '15.2(1)E2';
# 15.0EJ
else if (ver == '15.0(2)EJ')
         fixed_ver = '15.0(2)EJ1';
# 15.0EX
else if (ver == '15.0(2)EX' || ver == '15.0(2)EX1' || ver == '15.0(2)EX3' || ver == '15.0(2)EX4')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.0EY
else if (ver == '15.0(2)EY' || ver == '15.0(2)EY1' || ver == '15.0(2)EY3')
         fixed_ver = '15.2(1)E2';
# 15.0EZ
else if (ver == '15.0(2)EZ')
         fixed_ver = '15.0(2)SE6';
# 15.0SE
else if (ver == '15.0(2)SE' || ver == '15.0(2)SE1' || ver == '15.0(2)SE2' || ver == '15.0(2)SE3' || ver == '15.0(2)SE4' || ver == '15.0(2)SE5')
         fixed_ver = '15.0(2)SE6';
# 15.1GC
else if (ver == '15.1(2)GC' || ver == '15.1(2)GC1' || ver == '15.1(2)GC2' || ver == '15.1(4)GC' || ver == '15.1(4)GC1' || ver == '15.1(4)GC2')
         fixed_ver = '15.2(4)GC1';
# 15.1M
else if (ver == '15.1(4)M' || ver == '15.1(4)M0a' || ver == '15.1(4)M0b' || ver == '15.1(4)M1' || ver == '15.1(4)M2' || ver == '15.1(4)M3' || ver == '15.1(4)M3a' || ver == '15.1(4)M4' || ver == '15.1(4)M5' || ver == '15.1(4)M6' || ver == '15.1(4)M7')
         fixed_ver = '15.1(4)M8';
# 15.1MR
else if (ver == '15.1(1)MR' || ver == '15.1(1)MR1' || ver == '15.1(1)MR2' || ver == '15.1(1)MR3' || ver == '15.1(1)MR4' || ver == '15.1(1)MR5' || ver == '15.1(1)MR6' || ver == '15.1(3)MR')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.1MRA
else if (ver == '15.1(3)MRA' || ver == '15.1(3)MRA1' || ver == '15.1(3)MRA2')
         fixed_ver = '15.1(3)MRA3';
# 15.1S
else if (ver == '15.1(1)S' || ver == '15.1(1)S1' || ver == '15.1(1)S2' || ver == '15.1(2)S' || ver == '15.1(2)S1' || ver == '15.1(2)S2' || ver == '15.1(3)S' || ver == '15.1(3)S0a' || ver == '15.1(3)S1' || ver == '15.1(3)S2' || ver == '15.1(3)S3' || ver == '15.1(3)S4' || ver == '15.1(3)S5' || ver == '15.1(3)S5a' || ver == '15.1(3)S6')
         fixed_ver = '15.2(2)S0a or 15.2(4)S5';
# 15.1SG
else if (ver == '15.1(1)SG' || ver == '15.1(1)SG1' || ver == '15.1(1)SG2' || ver == '15.1(2)SG' || ver == '15.1(2)SG1' || ver == '15.1(2)SG2' || ver == '15.1(2)SG3')
         fixed_ver = '15.1(2)SG4';
# 15.1SNG
else if (ver == '15.1(2)SNG')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.1SNH
else if (ver == '15.1(2)SNH' || ver == '15.1(2)SNH1')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.1SNI
else if (ver == '15.1(2)SNI' || ver == '15.1(2)SNI1')
         fixed_ver = 'Refer to the vendor for a fix.';
# 15.1SY
else if (ver == '15.1(1)SY' || ver == '15.1(1)SY1' || ver == '15.1(1)SY2' || ver == '15.1(2)SY' || ver == '15.1(2)SY1')
         fixed_ver = '15.1(1)SY3 or 15.1(2)SY2';
# 15.1T
else if (ver == '15.1(1)T' || ver == '15.1(1)T1' || ver == '15.1(1)T2' || ver == '15.1(1)T3' || ver == '15.1(1)T4' || ver == '15.1(1)T5' || ver == '15.1(2)T' || ver == '15.1(2)T0a' || ver == '15.1(2)T1' || ver == '15.1(2)T2' || ver == '15.1(2)T2a' || ver == '15.1(2)T3' || ver == '15.1(2)T4' || ver == '15.1(2)T5' || ver == '15.1(3)T' || ver == '15.1(3)T1' || ver == '15.1(3)T2' || ver == '15.1(3)T3' || ver == '15.1(3)T4')
         fixed_ver = '15.1(4)M8';
# 15.1XB - no fix specified
else if (ver == '15.1(1)XB1' || ver == '15.1(1)XB2' || ver == '15.1(1)XB3' || ver == '15.1(4)XB4' || ver == '15.1(4)XB5' || ver == '15.1(4)XB5a' || ver == '15.1(4)XB6' || ver == '15.1(4)XB7' || ver == '15.1(4)XB8' || ver == '15.1(4)XB8a')
       fixed_ver = 'Refer to the vendor for a fix.';
# 15.2E
else if (ver == '15.2(1)E' || ver == '15.2(1)E1')
        fixed_ver = '15.2(1)E2';
# 15.2EY
else if (ver == '15.2(1)EY')
        fixed_ver = '15.2(1)E2';
# 15.2GC
else if (ver == '15.2(1)GC' || ver == '15.2(1)GC1' || ver == '15.2(1)GC2' || ver == '15.2(2)GC' || ver == '15.2(3)GC' || ver == '15.2(3)GC1' || ver == '15.2(4)GC')
        fixed_ver = '15.2(4)GC1';
# 15.2GCA - no fix specified
else if (ver == '15.2(3)GCA' || ver == '15.2(3)GCA1')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2M
else if (ver == '15.2(4)M' || ver == '15.2(4)M1' || ver == '15.2(4)M2' || ver == '15.2(4)M3' || ver == '15.2(4)M4' || ver == '15.2(4)M5')
        fixed_ver = '15.2(4)M6';
# 15.2S
else if (ver == '15.2(1)S' || ver == '15.2(1)S1' || ver == '15.2(1)S2' || ver == '15.2(2)S' || ver == '15.2(2)S1' || ver == '15.2(2)S2' || ver == '15.2(4)S' || ver == '15.2(4)S1' || ver == '15.2(4)S2' || ver == '15.2(4)S3' || ver == '15.2(4)S3a' || ver == '15.2(4)S4' || ver == '15.2(4)S4a')
        fixed_ver = '15.2(2)S0a or 15.2(4)S5';
# 15.2SNG
else if (ver == '15.2(2)SNG')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2SNH
else if (ver == '15.2(2)SNH' || ver == '15.2(2)SNH1')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2SNI
else if (ver == '15.2(2)SNI')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2T
else if (ver == '15.2(1)T' || ver == '15.2(1)T1' || ver == '15.2(1)T2' || ver == '15.2(1)T3' || ver == '15.2(1)T3a' || ver == '15.2(1)T4' || ver == '15.2(2)T' || ver == '15.2(2)T1' || ver == '15.2(2)T2' || ver == '15.2(2)T3' || ver == '15.2(2)T4' || ver == '15.2(3)T' || ver == '15.2(3)T1' ||   ver == '15.2(3)T2' || ver == '15.2(3)T3' || ver == '15.2(3)T4')
        fixed_ver = '15.2(4)M6';
# 15.2XA - no fix specified
else if (ver == '15.2(3)XA')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.2XB - no fix specified
else if (ver == '15.2(4)XB10')
        fixed_ver = 'Refer to the vendor for a fix.';
# 15.3M
else if (ver == '15.3(3)M')
        fixed_ver = '15.3(3)M1';
# 15.3S
else if (ver == '15.3(1)S' || ver == '15.3(1)S1' || ver == '15.3(1)S2' || ver == '15.3(2)S' || ver == '15.3(2)S0a' || ver == '15.3(2)S0xa' || ver == '15.3(2)S1' || ver == '15.3(2)S2' || ver == '15.3(3)S')
        fixed_ver = '15.3(3)S1';

if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"17\s[^\r\n]*\s(500|4500|848|4848)", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_subsys", "show subsys");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"ikev2\s+Library", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
