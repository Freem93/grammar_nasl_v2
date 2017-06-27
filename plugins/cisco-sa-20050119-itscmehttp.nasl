#TRUSTED 0c60ec9e2d737ce944952bec3047716929f71b499d998d599c8acf487664a903be24f61b2a7b47845a2f4d18de42ec9cbd104db8a5fedfdfc8a5f6696bc75e069f86675c9628ed91be887b83e5b8f6bfe5f5c15c071a5d8ca95dccfb7bc6d7e8ddcff28c333ab25d47354c54feccf32d75acd245ea92bdca4848cac67345aebdfd00616a3161faa88bdf7ea23da541656a85847ef23fb35fc6b24b87c7032fcd30ad5d8ee5b07d83c452abf758f45c33d6e0af4871406a135a667e30d3dbab74a26bf4a2fe0cfd75ebefc8d16c0ed3be6c3fcafc4c24ef62318f83a331c601647dada62cb4ef05cd98a60dc5591bbf43bfa16bfc4b33a15c7052dd7f74a3e0c7986b38257936c8b69a9ce14d726afe390e071de6276db29244fd8ad4186630c9a8043779e603fd5077b20203ed2aa7abcc6c5e9582379db1822567ec79f5444744e369ea681022eb9e5751ad4f1be02e08f538458341da153cac74e22db6d2aa6103e65c51aa3f5acc976364126c712ac30487b65a247dd3d6e8e103804d8f62fe34de5416411331afc595d9f336b607de03a4807cf80c50f2bd0663143bfe4e19328fcaed6049f114c90ad4175bec9f39db0b8ece9e5dbda8a112428911baa67d037b0cb294af9c050dedf4c0fb78c077be9736357eebf033de3b64cb86946631fe81fd10c6cc5b1450077b7b1420b7ea71a8599696a9513b642a8f4d8828d8
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00803b3fff.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48979);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2005-0186");
 script_bugtraq_id(12307);
 script_osvdb_id(13084);
 script_name(english:"Vulnerability in Cisco IOS Embedded Call Processing Solutions - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco Internetwork Operating System (IOS) Software release trains
12.1YD, 12.2T, 12.3 and 12.3T, when configured for the Cisco IOS
Telephony Service (ITS), Cisco CallManager Express (CME) or Survivable
Remote Site Telephony (SRST) may contain a vulnerability in processing
certain malformed control protocol messages.'
 );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2861f8b");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00803b3fff.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d064330c");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050119-itscme.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/01/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCee08584");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20050119-itscme");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(2)XZ2') flag++;
else if (version == '12.3(2)XZ1') flag++;
else if (version == '12.3(2)XZ') flag++;
else if (version == '12.3(4)XQ') flag++;
else if (version == '12.3(4)XK') flag++;
else if (version == '12.3(7)XJ1') flag++;
else if (version == '12.3(7)XJ') flag++;
else if (version == '12.3(4)XG1') flag++;
else if (version == '12.3(4)XG') flag++;
else if (version == '12.3(2)XF') flag++;
else if (version == '12.3(2)XE') flag++;
else if (version == '12.3(4)XD4') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(2)XC2') flag++;
else if (version == '12.3(2)XC') flag++;
else if (version == '12.3(2)XB3') flag++;
else if (version == '12.3(2)XB1') flag++;
else if (version == '12.3(2)XB') flag++;
else if (version == '12.3(2)XA4') flag++;
else if (version == '12.3(2)XA1') flag++;
else if (version == '12.3(2)XA') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2a') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.3(2)T6') flag++;
else if (version == '12.3(2)T5') flag++;
else if (version == '12.3(2)T4') flag++;
else if (version == '12.3(2)T3') flag++;
else if (version == '12.3(2)T2') flag++;
else if (version == '12.3(2)T1') flag++;
else if (version == '12.3(2)T') flag++;
else if (version == '12.3(5a)B5') flag++;
else if (version == '12.3(5a)B4') flag++;
else if (version == '12.3(5a)B3') flag++;
else if (version == '12.3(5a)B2') flag++;
else if (version == '12.3(5a)B1') flag++;
else if (version == '12.3(5a)B') flag++;
else if (version == '12.3(3)B1') flag++;
else if (version == '12.3(3)B') flag++;
else if (version == '12.3(1a)B') flag++;
else if (version == '12.3(6b)') flag++;
else if (version == '12.3(6a)') flag++;
else if (version == '12.3(6)') flag++;
else if (version == '12.3(5c)') flag++;
else if (version == '12.3(5b)') flag++;
else if (version == '12.3(5a)') flag++;
else if (version == '12.3(5)') flag++;
else if (version == '12.3(3g)') flag++;
else if (version == '12.3(3f)') flag++;
else if (version == '12.3(3e)') flag++;
else if (version == '12.3(3c)') flag++;
else if (version == '12.3(3b)') flag++;
else if (version == '12.3(3a)') flag++;
else if (version == '12.3(3)') flag++;
else if (version == '12.3(1a)') flag++;
else if (version == '12.3(1)') flag++;
else if (version == '12.2(13)ZP4') flag++;
else if (version == '12.2(13)ZP3') flag++;
else if (version == '12.2(13)ZP2') flag++;
else if (version == '12.2(13)ZP1') flag++;
else if (version == '12.2(13)ZP') flag++;
else if (version == '12.2(15)ZL1') flag++;
else if (version == '12.2(15)ZL') flag++;
else if (version == '12.2(15)ZJ5') flag++;
else if (version == '12.2(15)ZJ3') flag++;
else if (version == '12.2(15)ZJ2') flag++;
else if (version == '12.2(15)ZJ1') flag++;
else if (version == '12.2(15)ZJ') flag++;
else if (version == '12.2(13)ZH5') flag++;
else if (version == '12.2(13)ZH3') flag++;
else if (version == '12.2(13)ZH2') flag++;
else if (version == '12.2(13)ZH') flag++;
else if (version == '12.2(13)ZF2') flag++;
else if (version == '12.2(13)ZF1') flag++;
else if (version == '12.2(13)ZF') flag++;
else if (version == '12.2(13)ZE') flag++;
else if (version == '12.2(13)ZD4') flag++;
else if (version == '12.2(13)ZD3') flag++;
else if (version == '12.2(13)ZD2') flag++;
else if (version == '12.2(13)ZD1') flag++;
else if (version == '12.2(13)ZD') flag++;
else if (version == '12.2(13)ZC') flag++;
else if (version == '12.2(8)ZB8') flag++;
else if (version == '12.2(8)ZB7') flag++;
else if (version == '12.2(8)ZB6') flag++;
else if (version == '12.2(8)ZB5') flag++;
else if (version == '12.2(8)ZB4a') flag++;
else if (version == '12.2(8)ZB4') flag++;
else if (version == '12.2(8)ZB3') flag++;
else if (version == '12.2(8)ZB2') flag++;
else if (version == '12.2(8)ZB1') flag++;
else if (version == '12.2(8)YY4') flag++;
else if (version == '12.2(8)YY3') flag++;
else if (version == '12.2(8)YY2') flag++;
else if (version == '12.2(8)YY1') flag++;
else if (version == '12.2(8)YY') flag++;
else if (version == '12.2(8)YW3') flag++;
else if (version == '12.2(8)YW2') flag++;
else if (version == '12.2(8)YW1') flag++;
else if (version == '12.2(8)YW') flag++;
else if (version == '12.2(11)YV') flag++;
else if (version == '12.2(11)YU') flag++;
else if (version == '12.2(11)YT2') flag++;
else if (version == '12.2(11)YT1') flag++;
else if (version == '12.2(11)YT') flag++;
else if (version == '12.2(8)YN1') flag++;
else if (version == '12.2(8)YN') flag++;
else if (version == '12.2(8)YM') flag++;
else if (version == '12.2(8)YL') flag++;
else if (version == '12.2(8)YJ') flag++;
else if (version == '12.2(4)YH') flag++;
else if (version == '12.2(8)YD3') flag++;
else if (version == '12.2(8)YD2') flag++;
else if (version == '12.2(8)YD1') flag++;
else if (version == '12.2(8)YD') flag++;
else if (version == '12.2(2)YC4') flag++;
else if (version == '12.2(2)YC3') flag++;
else if (version == '12.2(2)YC2') flag++;
else if (version == '12.2(2)YC1') flag++;
else if (version == '12.2(2)YC') flag++;
else if (version == '12.2(4)YB') flag++;
else if (version == '12.2(4)YA7') flag++;
else if (version == '12.2(4)YA6') flag++;
else if (version == '12.2(4)YA2') flag++;
else if (version == '12.2(4)YA1') flag++;
else if (version == '12.2(4)YA') flag++;
else if (version == '12.2(4)XW') flag++;
else if (version == '12.2(2)XU') flag++;
else if (version == '12.2(2)XT3') flag++;
else if (version == '12.2(2)XT2') flag++;
else if (version == '12.2(2)XT') flag++;
else if (version == '12.2(4)XM4') flag++;
else if (version == '12.2(4)XM3') flag++;
else if (version == '12.2(4)XM2') flag++;
else if (version == '12.2(4)XM') flag++;
else if (version == '12.2(2)XG') flag++;
else if (version == '12.2(2)XB8') flag++;
else if (version == '12.2(2)XB7') flag++;
else if (version == '12.2(2)XB6') flag++;
else if (version == '12.2(2)XB5') flag++;
else if (version == '12.2(2)XB3') flag++;
else if (version == '12.2(2)XB2') flag++;
else if (version == '12.2(2)XB15') flag++;
else if (version == '12.2(2)XB14') flag++;
else if (version == '12.2(2)XB11') flag++;
else if (version == '12.2(15)T9') flag++;
else if (version == '12.2(15)T8') flag++;
else if (version == '12.2(15)T7') flag++;
else if (version == '12.2(15)T5') flag++;
else if (version == '12.2(15)T4e') flag++;
else if (version == '12.2(15)T4') flag++;
else if (version == '12.2(15)T2') flag++;
else if (version == '12.2(15)T12') flag++;
else if (version == '12.2(15)T11') flag++;
else if (version == '12.2(15)T10') flag++;
else if (version == '12.2(15)T1') flag++;
else if (version == '12.2(15)T') flag++;
else if (version == '12.2(13)T9') flag++;
else if (version == '12.2(13)T8') flag++;
else if (version == '12.2(13)T5') flag++;
else if (version == '12.2(13)T4') flag++;
else if (version == '12.2(13)T3') flag++;
else if (version == '12.2(13)T2') flag++;
else if (version == '12.2(13)T13') flag++;
else if (version == '12.2(13)T12') flag++;
else if (version == '12.2(13)T11') flag++;
else if (version == '12.2(13)T10') flag++;
else if (version == '12.2(13)T1a') flag++;
else if (version == '12.2(13)T1') flag++;
else if (version == '12.2(13)T') flag++;
else if (version == '12.2(11)T9') flag++;
else if (version == '12.2(11)T8') flag++;
else if (version == '12.2(11)T6') flag++;
else if (version == '12.2(11)T5') flag++;
else if (version == '12.2(11)T4') flag++;
else if (version == '12.2(11)T3') flag++;
else if (version == '12.2(11)T2') flag++;
else if (version == '12.2(11)T11') flag++;
else if (version == '12.2(11)T10') flag++;
else if (version == '12.2(11)T1') flag++;
else if (version == '12.2(11)T') flag++;
else if (version == '12.2(8)T8') flag++;
else if (version == '12.2(8)T5') flag++;
else if (version == '12.2(8)T4') flag++;
else if (version == '12.2(8)T3') flag++;
else if (version == '12.2(8)T2') flag++;
else if (version == '12.2(8)T10') flag++;
else if (version == '12.2(8)T1') flag++;
else if (version == '12.2(8)T') flag++;
else if (version == '12.2(15)MC1c') flag++;
else if (version == '12.2(15)MC1b') flag++;
else if (version == '12.2(15)MC1a') flag++;
else if (version == '12.2(8)BY2') flag++;
else if (version == '12.2(8)BY1') flag++;
else if (version == '12.2(8)BY') flag++;
else if (version == '12.2(16)BX3') flag++;
else if (version == '12.2(16)BX2') flag++;
else if (version == '12.2(16)BX1') flag++;
else if (version == '12.2(16)BX') flag++;
else if (version == '12.2(16)B2') flag++;
else if (version == '12.2(16)B1') flag++;
else if (version == '12.2(16)B') flag++;
else if (version == '12.2(15)B') flag++;
else if (version == '12.1(5)YI2') flag++;
else if (version == '12.1(5)YI1') flag++;
else if (version == '12.1(5)YI') flag++;
else if (version == '12.1(5)YE5') flag++;
else if (version == '12.1(5)YE4') flag++;
else if (version == '12.1(5)YE3') flag++;
else if (version == '12.1(5)YE2') flag++;
else if (version == '12.1(5)YE1') flag++;
else if (version == '12.1(5)YD6') flag++;
else if (version == '12.1(5)YD5') flag++;
else if (version == '12.1(5)YD4') flag++;
else if (version == '12.1(5)YD3') flag++;
else if (version == '12.1(5)YD2') flag++;
else if (version == '12.1(5)YD1') flag++;
else if (version == '12.1(5)YD') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"telephony-service", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"call-manager-fallback", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
