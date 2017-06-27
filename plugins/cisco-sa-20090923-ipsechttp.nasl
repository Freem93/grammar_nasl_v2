#TRUSTED 217c722cf0070bdc143a895c99cfe7d433c700bd48aba411780b2c217f7386f65c0b00de50eaebeed2f8665535be638e56ecc61e4f80ac190b6668251bc6f8d937dec7d96c8238c6b805b69bb38cc6073d491536dd84a48e0e666620862f20b56554b790086b1845f439f58752d1cf9efe009c64cbae3b073ba7a97808647966980d5e1a99cc7e2671cae025d1c82b56512eb79812479c1164eee51d331c9ef787b077e191143a5424b340118ab1fa26cbf9059d5e805010eb1117a026a2f1e61c75230104e1d2f54c61daed6be338119e5b55fb92d1d75ed77d1b6f66cd6f6f257fd6b3e7a36e2fc4f4375260b2e2b52e9c489879dc3bd82f1eaf01e049d4d01239a95d045485ace34198dacda9ad6a6510c103a74947863dfe379a7c2f3f0f3ff6e4c32675949a3292302b29160cf02b13375788a8c151c8303c0373e5c4e92bedd0b147d8aaf8fea2b089bd2f40b98f1229013f3e40669ac9a7577bf72dfd40f54cd56c954f12f5f100b0f4afc26d4ede41b58e96b98e651733d624ed166cb193e9d671d87514ec268fcadd052d9d7eb1660afa3abf3afa9bf20ab065f803eb2b838ac60a73798792066448dc6d9d69c42716982fad0660422c76612f1543374bf766381ce0aa6964e4fdf45316036cf3e6a7f16ee0bd9d24ccd4b0a37d8a023f9dbdf603a039bc2daf2a99ea88c78e971482c87c69fb22de6695289d2e88
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8117.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49044);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2009-2868");
 script_bugtraq_id(36497);
 script_osvdb_id(58336);
 script_xref(name:"CISCO-BUG-ID", value:"CSCee72997");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsy07555");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-ipsec");
 script_name(english:"Cisco IOS Software Internet Key Exchange Resource Exhaustion Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS devices that are configured for Internet Key Exchange (IKE)
protocol and certificate based authentication are vulnerable to a
resource exhaustion attack. Successful exploitation of this
vulnerability may result in the allocation of all available Phase 1
security associations (SA) and prevent the establishment of new IPsec
sessions.
 Cisco has released free software updates that address this
vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b05ed3b2");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8117.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c3f5a376");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-ipsec.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(4)XD9') flag++;
else if (version == '12.4(4)XD8') flag++;
else if (version == '12.4(4)XD7') flag++;
else if (version == '12.4(4)XD5') flag++;
else if (version == '12.4(4)XD4') flag++;
else if (version == '12.4(4)XD2') flag++;
else if (version == '12.4(4)XD12') flag++;
else if (version == '12.4(4)XD11') flag++;
else if (version == '12.4(4)XD10') flag++;
else if (version == '12.4(4)XD1') flag++;
else if (version == '12.4(4)XD') flag++;
else if (version == '12.4(4)XC7') flag++;
else if (version == '12.4(4)XC6') flag++;
else if (version == '12.4(4)XC5') flag++;
else if (version == '12.4(4)XC4') flag++;
else if (version == '12.4(4)XC3') flag++;
else if (version == '12.4(4)XC2') flag++;
else if (version == '12.4(4)XC1') flag++;
else if (version == '12.4(4)XC') flag++;
else if (version == '12.4(2)XB9') flag++;
else if (version == '12.4(2)XB8') flag++;
else if (version == '12.4(2)XB7') flag++;
else if (version == '12.4(2)XB6') flag++;
else if (version == '12.4(2)XB5') flag++;
else if (version == '12.4(2)XB4') flag++;
else if (version == '12.4(2)XB3') flag++;
else if (version == '12.4(2)XB2') flag++;
else if (version == '12.4(2)XB10') flag++;
else if (version == '12.4(2)XB1') flag++;
else if (version == '12.4(2)XB') flag++;
else if (version == '12.4(2)XA2') flag++;
else if (version == '12.4(2)XA1') flag++;
else if (version == '12.4(2)XA') flag++;
else if (version == '12.4(6)T') flag++;
else if (version == '12.4(4)T7') flag++;
else if (version == '12.4(4)T6') flag++;
else if (version == '12.4(4)T5') flag++;
else if (version == '12.4(4)T4') flag++;
else if (version == '12.4(4)T3') flag++;
else if (version == '12.4(4)T2') flag++;
else if (version == '12.4(4)T1') flag++;
else if (version == '12.4(4)T') flag++;
else if (version == '12.4(2)T6') flag++;
else if (version == '12.4(2)T5') flag++;
else if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(7)') flag++;
else if (version == '12.4(5a)') flag++;
else if (version == '12.4(5)') flag++;
else if (version == '12.4(3f)') flag++;
else if (version == '12.4(3e)') flag++;
else if (version == '12.4(3d)') flag++;
else if (version == '12.4(3c)') flag++;
else if (version == '12.4(3b)') flag++;
else if (version == '12.4(3a)') flag++;
else if (version == '12.4(3)') flag++;
else if (version == '12.4(1c)') flag++;
else if (version == '12.4(1b)') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(11)YZ2') flag++;
else if (version == '12.3(11)YZ1') flag++;
else if (version == '12.3(11)YZ') flag++;
else if (version == '12.3(14)YX9') flag++;
else if (version == '12.3(14)YX8') flag++;
else if (version == '12.3(14)YX7') flag++;
else if (version == '12.3(14)YX4') flag++;
else if (version == '12.3(14)YX3') flag++;
else if (version == '12.3(14)YX2') flag++;
else if (version == '12.3(14)YX15') flag++;
else if (version == '12.3(14)YX14') flag++;
else if (version == '12.3(14)YX13') flag++;
else if (version == '12.3(14)YX12') flag++;
else if (version == '12.3(14)YX11') flag++;
else if (version == '12.3(14)YX10') flag++;
else if (version == '12.3(14)YX1') flag++;
else if (version == '12.3(14)YX') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS2') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YQ8') flag++;
else if (version == '12.3(14)YQ7') flag++;
else if (version == '12.3(14)YQ6') flag++;
else if (version == '12.3(14)YQ5') flag++;
else if (version == '12.3(14)YQ4') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(11)YK3') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(8)YI3') flag++;
else if (version == '12.3(8)YI2') flag++;
else if (version == '12.3(8)YI1') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG6') flag++;
else if (version == '12.3(8)YG5') flag++;
else if (version == '12.3(8)YG4') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XX2d') flag++;
else if (version == '12.3(8)XX1') flag++;
else if (version == '12.3(8)XX') flag++;
else if (version == '12.3(7)XS2') flag++;
else if (version == '12.3(7)XS1') flag++;
else if (version == '12.3(7)XS') flag++;
else if (version == '12.3(7)XR7') flag++;
else if (version == '12.3(7)XR6') flag++;
else if (version == '12.3(7)XR5') flag++;
else if (version == '12.3(7)XR4') flag++;
else if (version == '12.3(7)XR3') flag++;
else if (version == '12.3(7)XR2') flag++;
else if (version == '12.3(7)XR') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(14)T7') flag++;
else if (version == '12.3(14)T6') flag++;
else if (version == '12.3(14)T5') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T9') flag++;
else if (version == '12.3(11)T8') flag++;
else if (version == '12.3(11)T7') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T11') flag++;
else if (version == '12.3(11)T10') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.2(2)XU1') flag++;
else if (version == '12.2(2)XT1') flag++;
else if (version == '12.2(1)XS1') flag++;
else if (version == '12.2(33)XN1') flag++;
else if (version == '12.2(33)SXI1') flag++;
else if (version == '12.2(33)SXI') flag++;
else if (version == '12.2(33)SXH5') flag++;
else if (version == '12.2(33)SXH4') flag++;
else if (version == '12.2(33)SXH3a') flag++;
else if (version == '12.2(33)SXH3') flag++;
else if (version == '12.2(33)SXH2a') flag++;
else if (version == '12.2(33)SXH2') flag++;
else if (version == '12.2(33)SXH1') flag++;
else if (version == '12.2(33)SXH') flag++;
else if (version == '12.2(25)SW') flag++;
else if (version == '12.2(33)SRD2') flag++;
else if (version == '12.2(33)SRD1') flag++;
else if (version == '12.2(33)SRD') flag++;
else if (version == '12.2(33)SRC4') flag++;
else if (version == '12.2(33)SRC3') flag++;
else if (version == '12.2(33)SRC2') flag++;
else if (version == '12.2(33)SRC1') flag++;
else if (version == '12.2(33)SRC') flag++;
else if (version == '12.2(33)SRB5a') flag++;
else if (version == '12.2(33)SRB5') flag++;
else if (version == '12.2(33)SRB4') flag++;
else if (version == '12.2(33)SRB3') flag++;
else if (version == '12.2(33)SRB2') flag++;
else if (version == '12.2(33)SRB1') flag++;
else if (version == '12.2(33)SRB') flag++;
else if (version == '12.2(33)SRA7') flag++;
else if (version == '12.2(33)SRA6') flag++;
else if (version == '12.2(33)SRA5') flag++;
else if (version == '12.2(33)SRA4') flag++;
else if (version == '12.2(33)SRA3') flag++;
else if (version == '12.2(33)SRA2') flag++;
else if (version == '12.2(33)SRA1') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(50)SE1') flag++;
else if (version == '12.2(50)SE') flag++;
else if (version == '12.2(46)SE') flag++;
else if (version == '12.2(44)SE6') flag++;
else if (version == '12.2(44)SE5') flag++;
else if (version == '12.2(44)SE3') flag++;
else if (version == '12.2(44)SE2') flag++;
else if (version == '12.2(44)SE1') flag++;
else if (version == '12.2(44)SE') flag++;
else if (version == '12.2(40)SE') flag++;
else if (version == '12.2(33)SCB3') flag++;
else if (version == '12.2(33)SCB2') flag++;
else if (version == '12.2(33)SCB1') flag++;
else if (version == '12.2(33)SCB') flag++;
else if (version == '12.2(33)SCA2') flag++;
else if (version == '12.2(33)SCA1') flag++;
else if (version == '12.2(33)SCA') flag++;
else if (version == '12.2(33)SB4') flag++;
else if (version == '12.2(33)SB3') flag++;
else if (version == '12.2(33)SB2') flag++;
else if (version == '12.2(33)SB1') flag++;
else if (version == '12.2(33)SB') flag++;
else if (version == '12.2(33)IRC') flag++;
else if (version == '12.2(33)IRB') flag++;
else if (version == '12.2(33)IRA') flag++;


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_crypto_key_mypubkey_rsa", "show crypto key mypubkey rsa");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Key Data:", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s500\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s4500\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s848\s", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"\s4848\s", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_crypto_isakmp_policy", "show crypto isakmp policy");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Rivest-Shamir-Adleman Signature", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
