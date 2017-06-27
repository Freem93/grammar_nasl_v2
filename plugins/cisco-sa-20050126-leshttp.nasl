#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00803be77c.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48982);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2005-0197");
 script_bugtraq_id(12369);
 script_osvdb_id(13191);
 script_xref(name:"CERT", value:"583638");
 script_name(english:"Crafted Packet Causes Reload on Cisco Routers");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'Cisco Routers running Internetwork Operating System (IOS) that supports
Multi Protocol Label Switching (MPLS) are vulnerable to a Denial of
Service (DoS) attack on interfaces where MPLS is not configured. A
system that supports MPLS is vulnerable even if that system is not
configured for MPLS.
The vulnerability is only present in Cisco IOS release trains based on
12.1T, 12.2, 12.2T, 12.3 and 12.3T. Releases based on 12.1 mainline,
12.1E and all releases prior to 12.1 are not vulnerable. 
Cisco has made free software available to address this vulnerability. 
There are workarounds available to mitigate the effects.'
 );
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?795df75a");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00803be77c.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?ec7708a5");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20050126-les."
 );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(16);
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/26");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/01/26");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCeb56909");
 script_xref(name:"CISCO-BUG-ID", value:"CSCec86420");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20050126-les");
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}
include("cisco_func.inc");

#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.3(2)XA4')
  security_warning(0);
else if (version == '12.3(2)T4')
  security_warning(0);
else if (version == '12.3(2)T3')
  security_warning(0);
else if (version == '12.3(2)T2')
  security_warning(0);
else if (version == '12.3(2)T1')
  security_warning(0);
else if (version == '12.3(2)T')
  security_warning(0);
else if (version == '12.3(1a)BW')
  security_warning(0);
else if (version == '12.3(3)B1')
  security_warning(0);
else if (version == '12.3(3)B')
  security_warning(0);
else if (version == '12.3(1a)B')
  security_warning(0);
else if (version == '12.3(3e)')
  security_warning(0);
else if (version == '12.3(3c)')
  security_warning(0);
else if (version == '12.3(3b)')
  security_warning(0);
else if (version == '12.3(3a)')
  security_warning(0);
else if (version == '12.3(3)')
  security_warning(0);
else if (version == '12.3(1a)')
  security_warning(0);
else if (version == '12.3(1)')
  security_warning(0);
else if (version == '12.2(15)ZJ5')
  security_warning(0);
else if (version == '12.2(15)ZJ3')
  security_warning(0);
else if (version == '12.2(15)ZJ2')
  security_warning(0);
else if (version == '12.2(15)ZJ1')
  security_warning(0);
else if (version == '12.2(15)ZJ')
  security_warning(0);
else if (version == '12.2(13)ZE')
  security_warning(0);
else if (version == '12.2(13)ZD4')
  security_warning(0);
else if (version == '12.2(13)ZD3')
  security_warning(0);
else if (version == '12.2(13)ZD2')
  security_warning(0);
else if (version == '12.2(13)ZD1')
  security_warning(0);
else if (version == '12.2(13)ZD')
  security_warning(0);
else if (version == '12.2(14)ZA7')
  security_warning(0);
else if (version == '12.2(14)ZA6')
  security_warning(0);
else if (version == '12.2(14)ZA5')
  security_warning(0);
else if (version == '12.2(14)ZA4')
  security_warning(0);
else if (version == '12.2(14)ZA3')
  security_warning(0);
else if (version == '12.2(14)ZA2')
  security_warning(0);
else if (version == '12.2(14)ZA1')
  security_warning(0);
else if (version == '12.2(14)ZA')
  security_warning(0);
else if (version == '12.2(9)ZA')
  security_warning(0);
else if (version == '12.2(11)YZ2')
  security_warning(0);
else if (version == '12.2(11)YZ1')
  security_warning(0);
else if (version == '12.2(11)YZ')
  security_warning(0);
else if (version == '12.2(8)YY4')
  security_warning(0);
else if (version == '12.2(8)YY3')
  security_warning(0);
else if (version == '12.2(8)YY2')
  security_warning(0);
else if (version == '12.2(8)YY1')
  security_warning(0);
else if (version == '12.2(8)YY')
  security_warning(0);
else if (version == '12.2(11)YX1')
  security_warning(0);
else if (version == '12.2(11)YX')
  security_warning(0);
else if (version == '12.2(11)YT2')
  security_warning(0);
else if (version == '12.2(11)YT1')
  security_warning(0);
else if (version == '12.2(11)YT')
  security_warning(0);
else if (version == '12.2(8)YN')
  security_warning(0);
else if (version == '12.2(8)YJ')
  security_warning(0);
else if (version == '12.2(8)YD3')
  security_warning(0);
else if (version == '12.2(8)YD2')
  security_warning(0);
else if (version == '12.2(8)YD1')
  security_warning(0);
else if (version == '12.2(8)YD')
  security_warning(0);
else if (version == '12.2(4)XV5')
  security_warning(0);
else if (version == '12.2(4)XV4a')
  security_warning(0);
else if (version == '12.2(4)XV4')
  security_warning(0);
else if (version == '12.2(4)XV3')
  security_warning(0);
else if (version == '12.2(4)XV2')
  security_warning(0);
else if (version == '12.2(4)XV1')
  security_warning(0);
else if (version == '12.2(4)XV')
  security_warning(0);
else if (version == '12.2(2)XU')
  security_warning(0);
else if (version == '12.2(2)XT3')
  security_warning(0);
else if (version == '12.2(2)XT2')
  security_warning(0);
else if (version == '12.2(2)XT')
  security_warning(0);
else if (version == '12.2(2)XN')
  security_warning(0);
else if (version == '12.2(4)XL6')
  security_warning(0);
else if (version == '12.2(4)XL5')
  security_warning(0);
else if (version == '12.2(4)XL4')
  security_warning(0);
else if (version == '12.2(4)XL3')
  security_warning(0);
else if (version == '12.2(4)XL')
  security_warning(0);
else if (version == '12.2(2)XK3')
  security_warning(0);
else if (version == '12.2(2)XK2')
  security_warning(0);
else if (version == '12.2(2)XK')
  security_warning(0);
else if (version == '12.2(2)XG1')
  security_warning(0);
else if (version == '12.2(2)XG')
  security_warning(0);
else if (version == '12.2(4)XF1')
  security_warning(0);
else if (version == '12.2(2)XB8')
  security_warning(0);
else if (version == '12.2(2)XB7')
  security_warning(0);
else if (version == '12.2(2)XB6')
  security_warning(0);
else if (version == '12.2(2)XB5')
  security_warning(0);
else if (version == '12.2(2)XB3')
  security_warning(0);
else if (version == '12.2(2)XB2')
  security_warning(0);
else if (version == '12.2(2)XB15')
  security_warning(0);
else if (version == '12.2(2)XB14')
  security_warning(0);
else if (version == '12.2(2)XB12')
  security_warning(0);
else if (version == '12.2(2)XB11')
  security_warning(0);
else if (version == '12.2(2)XB10')
  security_warning(0);
else if (version == '12.2(2)XB1')
  security_warning(0);
else if (version == '12.2(2)XA5')
  security_warning(0);
else if (version == '12.2(2)XA4')
  security_warning(0);
else if (version == '12.2(2)XA3')
  security_warning(0);
else if (version == '12.2(2)XA2')
  security_warning(0);
else if (version == '12.2(2)XA1')
  security_warning(0);
else if (version == '12.2(2)XA')
  security_warning(0);
else if (version == '12.2(15)T5')
  security_warning(0);
else if (version == '12.2(15)T4e')
  security_warning(0);
else if (version == '12.2(15)T4')
  security_warning(0);
else if (version == '12.2(15)T2')
  security_warning(0);
else if (version == '12.2(15)T1')
  security_warning(0);
else if (version == '12.2(15)T')
  security_warning(0);
else if (version == '12.2(13)T9')
  security_warning(0);
else if (version == '12.2(13)T8')
  security_warning(0);
else if (version == '12.2(13)T5')
  security_warning(0);
else if (version == '12.2(13)T4')
  security_warning(0);
else if (version == '12.2(13)T3')
  security_warning(0);
else if (version == '12.2(13)T2')
  security_warning(0);
else if (version == '12.2(13)T13')
  security_warning(0);
else if (version == '12.2(13)T12')
  security_warning(0);
else if (version == '12.2(13)T11')
  security_warning(0);
else if (version == '12.2(13)T10')
  security_warning(0);
else if (version == '12.2(13)T1a')
  security_warning(0);
else if (version == '12.2(13)T1')
  security_warning(0);
else if (version == '12.2(13)T')
  security_warning(0);
else if (version == '12.2(11)T9')
  security_warning(0);
else if (version == '12.2(11)T8')
  security_warning(0);
else if (version == '12.2(11)T6')
  security_warning(0);
else if (version == '12.2(11)T5')
  security_warning(0);
else if (version == '12.2(11)T3')
  security_warning(0);
else if (version == '12.2(11)T2')
  security_warning(0);
else if (version == '12.2(11)T11')
  security_warning(0);
else if (version == '12.2(11)T10')
  security_warning(0);
else if (version == '12.2(11)T1')
  security_warning(0);
else if (version == '12.2(11)T')
  security_warning(0);
else if (version == '12.2(8)T8')
  security_warning(0);
else if (version == '12.2(8)T5')
  security_warning(0);
else if (version == '12.2(8)T4')
  security_warning(0);
else if (version == '12.2(8)T3')
  security_warning(0);
else if (version == '12.2(8)T2')
  security_warning(0);
else if (version == '12.2(8)T10')
  security_warning(0);
else if (version == '12.2(8)T1')
  security_warning(0);
else if (version == '12.2(8)T')
  security_warning(0);
else if (version == '12.2(4)T7')
  security_warning(0);
else if (version == '12.2(4)T6')
  security_warning(0);
else if (version == '12.2(4)T5')
  security_warning(0);
else if (version == '12.2(4)T3')
  security_warning(0);
else if (version == '12.2(4)T2')
  security_warning(0);
else if (version == '12.2(4)T1')
  security_warning(0);
else if (version == '12.2(4)T')
  security_warning(0);
else if (version == '12.2(2)T4')
  security_warning(0);
else if (version == '12.2(2)T3')
  security_warning(0);
else if (version == '12.2(2)T2')
  security_warning(0);
else if (version == '12.2(2)T1')
  security_warning(0);
else if (version == '12.2(2)T')
  security_warning(0);
else if (version == '12.2(14)SZ6')
  security_warning(0);
else if (version == '12.2(14)SZ5')
  security_warning(0);
else if (version == '12.2(14)SZ4')
  security_warning(0);
else if (version == '12.2(14)SZ3')
  security_warning(0);
else if (version == '12.2(14)SZ2')
  security_warning(0);
else if (version == '12.2(14)SZ1')
  security_warning(0);
else if (version == '12.2(14)SZ')
  security_warning(0);
else if (version == '12.2(14)SY5')
  security_warning(0);
else if (version == '12.2(14)SY4')
  security_warning(0);
else if (version == '12.2(14)SY3')
  security_warning(0);
else if (version == '12.2(14)SY2')
  security_warning(0);
else if (version == '12.2(14)SY1')
  security_warning(0);
else if (version == '12.2(14)SY')
  security_warning(0);
else if (version == '12.2(17b)SXA2')
  security_warning(0);
else if (version == '12.2(17b)SXA')
  security_warning(0);
else if (version == '12.2(17a)SX4')
  security_warning(0);
else if (version == '12.2(17a)SX3')
  security_warning(0);
else if (version == '12.2(17a)SX2')
  security_warning(0);
else if (version == '12.2(17a)SX1')
  security_warning(0);
else if (version == '12.2(17a)SX')
  security_warning(0);
else if (version == '12.2(14)SX1')
  security_warning(0);
else if (version == '12.2(14)SX')
  security_warning(0);
else if (version == '12.2(14)S9')
  security_warning(0);
else if (version == '12.2(14)S8')
  security_warning(0);
else if (version == '12.2(14)S7')
  security_warning(0);
else if (version == '12.2(14)S5')
  security_warning(0);
else if (version == '12.2(14)S3')
  security_warning(0);
else if (version == '12.2(14)S2')
  security_warning(0);
else if (version == '12.2(14)S1')
  security_warning(0);
else if (version == '12.2(14)S')
  security_warning(0);
else if (version == '12.2(9)S')
  security_warning(0);
else if (version == '12.2(15)MC1')
  security_warning(0);
else if (version == '12.2(8)MC2d')
  security_warning(0);
else if (version == '12.2(8)MC2c')
  security_warning(0);
else if (version == '12.2(8)MC2b')
  security_warning(0);
else if (version == '12.2(8)MC2')
  security_warning(0);
else if (version == '12.2(8)MC1')
  security_warning(0);
else if (version == '12.2(12h)M1')
  security_warning(0);
else if (version == '12.2(12b)M1')
  security_warning(0);
else if (version == '12.2(6c)M1')
  security_warning(0);
else if (version == '12.2(1)M0')
  security_warning(0);
else if (version == '12.2(2)DX3')
  security_warning(0);
else if (version == '12.2(1)DX1')
  security_warning(0);
else if (version == '12.2(1)DX')
  security_warning(0);
else if (version == '12.2(2)DD4')
  security_warning(0);
else if (version == '12.2(2)DD3')
  security_warning(0);
else if (version == '12.2(2)DD2')
  security_warning(0);
else if (version == '12.2(2)DD1')
  security_warning(0);
else if (version == '12.2(2)DD')
  security_warning(0);
else if (version == '12.2(12)DA5')
  security_warning(0);
else if (version == '12.2(12)DA4')
  security_warning(0);
else if (version == '12.2(12)DA3')
  security_warning(0);
else if (version == '12.2(12)DA2')
  security_warning(0);
else if (version == '12.2(12)DA1')
  security_warning(0);
else if (version == '12.2(12)DA')
  security_warning(0);
else if (version == '12.2(10)DA2')
  security_warning(0);
else if (version == '12.2(10)DA1')
  security_warning(0);
else if (version == '12.2(10)DA')
  security_warning(0);
else if (version == '12.2(7)DA')
  security_warning(0);
else if (version == '12.2(5)DA1')
  security_warning(0);
else if (version == '12.2(5)DA')
  security_warning(0);
else if (version == '12.2(1b)DA1')
  security_warning(0);
else if (version == '12.2(1b)DA')
  security_warning(0);
else if (version == '12.2(11)CY')
  security_warning(0);
else if (version == '12.2(15)CX1')
  security_warning(0);
else if (version == '12.2(15)CX')
  security_warning(0);
else if (version == '12.2(11)CX')
  security_warning(0);
else if (version == '12.2(15)BZ2')
  security_warning(0);
else if (version == '12.2(4)BZ2')
  security_warning(0);
else if (version == '12.2(4)BZ1')
  security_warning(0);
else if (version == '12.2(2)BY3')
  security_warning(0);
else if (version == '12.2(2)BY2')
  security_warning(0);
else if (version == '12.2(2)BY1')
  security_warning(0);
else if (version == '12.2(16)BX3')
  security_warning(0);
else if (version == '12.2(16)BX2')
  security_warning(0);
else if (version == '12.2(16)BX1')
  security_warning(0);
else if (version == '12.2(16)BX')
  security_warning(0);
else if (version == '12.2(15)BX')
  security_warning(0);
else if (version == '12.2(2)BX1')
  security_warning(0);
else if (version == '12.2(2)BX')
  security_warning(0);
else if (version == '12.2(4)BW2')
  security_warning(0);
else if (version == '12.2(4)BW1a')
  security_warning(0);
else if (version == '12.2(4)BW1')
  security_warning(0);
else if (version == '12.2(4)BW')
  security_warning(0);
else if (version == '12.2(15)BC1g')
  security_warning(0);
else if (version == '12.2(15)BC1f')
  security_warning(0);
else if (version == '12.2(15)BC1e')
  security_warning(0);
else if (version == '12.2(15)BC1d')
  security_warning(0);
else if (version == '12.2(15)BC1c')
  security_warning(0);
else if (version == '12.2(15)BC1b')
  security_warning(0);
else if (version == '12.2(15)BC1a')
  security_warning(0);
else if (version == '12.2(15)BC1')
  security_warning(0);
else if (version == '12.2(11)BC3d')
  security_warning(0);
else if (version == '12.2(11)BC3c')
  security_warning(0);
else if (version == '12.2(11)BC3b')
  security_warning(0);
else if (version == '12.2(11)BC3a')
  security_warning(0);
else if (version == '12.2(11)BC3')
  security_warning(0);
else if (version == '12.2(11)BC2a')
  security_warning(0);
else if (version == '12.2(11)BC2')
  security_warning(0);
else if (version == '12.2(11)BC1b')
  security_warning(0);
else if (version == '12.2(11)BC1a')
  security_warning(0);
else if (version == '12.2(11)BC1')
  security_warning(0);
else if (version == '12.2(8)BC2a')
  security_warning(0);
else if (version == '12.2(8)BC2')
  security_warning(0);
else if (version == '12.2(8)BC1')
  security_warning(0);
else if (version == '12.2(4)BC1b')
  security_warning(0);
else if (version == '12.2(4)BC1a')
  security_warning(0);
else if (version == '12.2(4)BC1')
  security_warning(0);
else if (version == '12.2(16)B2')
  security_warning(0);
else if (version == '12.2(16)B1')
  security_warning(0);
else if (version == '12.2(16)B')
  security_warning(0);
else if (version == '12.2(15)B')
  security_warning(0);
else if (version == '12.2(4)B8')
  security_warning(0);
else if (version == '12.2(4)B7')
  security_warning(0);
else if (version == '12.2(4)B6')
  security_warning(0);
else if (version == '12.2(4)B5')
  security_warning(0);
else if (version == '12.2(4)B4')
  security_warning(0);
else if (version == '12.2(4)B3')
  security_warning(0);
else if (version == '12.2(4)B2')
  security_warning(0);
else if (version == '12.2(4)B1')
  security_warning(0);
else if (version == '12.2(4)B')
  security_warning(0);
else if (version == '12.2(2)B7')
  security_warning(0);
else if (version == '12.2(2)B6')
  security_warning(0);
else if (version == '12.2(2)B5')
  security_warning(0);
else if (version == '12.2(2)B4')
  security_warning(0);
else if (version == '12.2(2)B3')
  security_warning(0);
else if (version == '12.2(2)B2')
  security_warning(0);
else if (version == '12.2(2)B1')
  security_warning(0);
else if (version == '12.2(2)B')
  security_warning(0);
else if (version == '12.2(19a)')
  security_warning(0);
else if (version == '12.2(19)')
  security_warning(0);
else if (version == '12.2(17b)')
  security_warning(0);
else if (version == '12.2(17a)')
  security_warning(0);
else if (version == '12.2(17)')
  security_warning(0);
else if (version == '12.2(16c)')
  security_warning(0);
else if (version == '12.2(16b)')
  security_warning(0);
else if (version == '12.2(16a)')
  security_warning(0);
else if (version == '12.2(16)')
  security_warning(0);
else if (version == '12.2(13c)')
  security_warning(0);
else if (version == '12.2(13b)')
  security_warning(0);
else if (version == '12.2(13a)')
  security_warning(0);
else if (version == '12.2(13)')
  security_warning(0);
else if (version == '12.2(12m)')
  security_warning(0);
else if (version == '12.2(12l)')
  security_warning(0);
else if (version == '12.2(12k)')
  security_warning(0);
else if (version == '12.2(12j)')
  security_warning(0);
else if (version == '12.2(12i)')
  security_warning(0);
else if (version == '12.2(12h)')
  security_warning(0);
else if (version == '12.2(12g)')
  security_warning(0);
else if (version == '12.2(12f)')
  security_warning(0);
else if (version == '12.2(12e)')
  security_warning(0);
else if (version == '12.2(12c)')
  security_warning(0);
else if (version == '12.2(12b)')
  security_warning(0);
else if (version == '12.2(12a)')
  security_warning(0);
else if (version == '12.2(12)')
  security_warning(0);
else if (version == '12.2(10d)')
  security_warning(0);
else if (version == '12.2(10b)')
  security_warning(0);
else if (version == '12.2(10a)')
  security_warning(0);
else if (version == '12.2(10)')
  security_warning(0);
else if (version == '12.2(7g)')
  security_warning(0);
else if (version == '12.2(7c)')
  security_warning(0);
else if (version == '12.2(7b)')
  security_warning(0);
else if (version == '12.2(7a)')
  security_warning(0);
else if (version == '12.2(7)')
  security_warning(0);
else if (version == '12.2(6j)')
  security_warning(0);
else if (version == '12.2(6i)')
  security_warning(0);
else if (version == '12.2(6h)')
  security_warning(0);
else if (version == '12.2(6g)')
  security_warning(0);
else if (version == '12.2(6f)')
  security_warning(0);
else if (version == '12.2(6e)')
  security_warning(0);
else if (version == '12.2(6d)')
  security_warning(0);
else if (version == '12.2(6c)')
  security_warning(0);
else if (version == '12.2(6b)')
  security_warning(0);
else if (version == '12.2(6a)')
  security_warning(0);
else if (version == '12.2(6)')
  security_warning(0);
else if (version == '12.2(5d)')
  security_warning(0);
else if (version == '12.2(5c)')
  security_warning(0);
else if (version == '12.2(5b)')
  security_warning(0);
else if (version == '12.2(5a)')
  security_warning(0);
else if (version == '12.2(5)')
  security_warning(0);
else if (version == '12.2(3g)')
  security_warning(0);
else if (version == '12.2(3d)')
  security_warning(0);
else if (version == '12.2(3c)')
  security_warning(0);
else if (version == '12.2(3b)')
  security_warning(0);
else if (version == '12.2(3a)')
  security_warning(0);
else if (version == '12.2(3)')
  security_warning(0);
else if (version == '12.2(1d)')
  security_warning(0);
else if (version == '12.2(1c)')
  security_warning(0);
else if (version == '12.2(1b)')
  security_warning(0);
else if (version == '12.2(1a)')
  security_warning(0);
else if (version == '12.2(1)')
  security_warning(0);
else if (version == '12.1(5)YD6')
  security_warning(0);
else if (version == '12.1(5)YD5')
  security_warning(0);
else if (version == '12.1(5)YD4')
  security_warning(0);
else if (version == '12.1(5)YD3')
  security_warning(0);
else if (version == '12.1(5)YD2')
  security_warning(0);
else if (version == '12.1(5)YD1')
  security_warning(0);
else if (version == '12.1(5)YD')
  security_warning(0);
else if (version == '12.1(5)YB5')
  security_warning(0);
else if (version == '12.1(5)YB4')
  security_warning(0);
else if (version == '12.1(5)YB')
  security_warning(0);
else if (version == '12.1(4)XY8')
  security_warning(0);
else if (version == '12.1(4)XY7')
  security_warning(0);
else if (version == '12.1(4)XY6')
  security_warning(0);
else if (version == '12.1(4)XY5')
  security_warning(0);
else if (version == '12.1(4)XY4')
  security_warning(0);
else if (version == '12.1(4)XY3')
  security_warning(0);
else if (version == '12.1(4)XY1')
  security_warning(0);
else if (version == '12.1(5)XV')
  security_warning(0);
else if (version == '12.1(3)XQ3')
  security_warning(0);
else if (version == '12.1(3)XQ2')
  security_warning(0);
else if (version == '12.1(3)XQ1')
  security_warning(0);
else if (version == '12.1(3)XQ')
  security_warning(0);
else if (version == '12.1(5)XM8')
  security_warning(0);
else if (version == '12.1(5)XM7')
  security_warning(0);
else if (version == '12.1(5)XM6')
  security_warning(0);
else if (version == '12.1(5)XM5')
  security_warning(0);
else if (version == '12.1(5)XM4')
  security_warning(0);
else if (version == '12.1(5)XM3')
  security_warning(0);
else if (version == '12.1(5)XM2')
  security_warning(0);
else if (version == '12.1(5)XM1')
  security_warning(0);
else if (version == '12.1(5)XM')
  security_warning(0);
else if (version == '12.1(3a)XI9')
  security_warning(0);
else if (version == '12.1(3a)XI8')
  security_warning(0);
else if (version == '12.1(3a)XI7')
  security_warning(0);
else if (version == '12.1(3a)XI6')
  security_warning(0);
else if (version == '12.1(3a)XI5')
  security_warning(0);
else if (version == '12.1(3a)XI4')
  security_warning(0);
else if (version == '12.1(3a)XI3')
  security_warning(0);
else if (version == '12.1(3a)XI2')
  security_warning(0);
else if (version == '12.1(3a)XI1')
  security_warning(0);
else if (version == '12.1(3)XI')
  security_warning(0);
else if (version == '12.1(5)T9')
  security_warning(0);
else if (version == '12.1(5)T8b')
  security_warning(0);
else if (version == '12.1(5)T8a')
  security_warning(0);
else if (version == '12.1(5)T8')
  security_warning(0);
else if (version == '12.1(5)T7')
  security_warning(0);
else if (version == '12.1(5)T6')
  security_warning(0);
else if (version == '12.1(5)T5')
  security_warning(0);
else if (version == '12.1(5)T4')
  security_warning(0);
else if (version == '12.1(5)T3')
  security_warning(0);
else if (version == '12.1(5)T20')
  security_warning(0);
else if (version == '12.1(5)T2')
  security_warning(0);
else if (version == '12.1(5)T19')
  security_warning(0);
else if (version == '12.1(5)T18')
  security_warning(0);
else if (version == '12.1(5)T17')
  security_warning(0);
else if (version == '12.1(5)T15')
  security_warning(0);
else if (version == '12.1(5)T14')
  security_warning(0);
else if (version == '12.1(5)T12')
  security_warning(0);
else if (version == '12.1(5)T10')
  security_warning(0);
else if (version == '12.1(5)T1')
  security_warning(0);
else if (version == '12.1(5)T')
  security_warning(0);
else if (version == '12.1(3a)T8')
  security_warning(0);
else if (version == '12.1(3a)T7')
  security_warning(0);
else if (version == '12.1(3a)T6')
  security_warning(0);
else if (version == '12.1(3a)T3')
  security_warning(0);
else if (version == '12.1(3a)T2')
  security_warning(0);
else if (version == '12.1(3a)T1')
  security_warning(0);
else if (version == '12.1(3)T')
  security_warning(0);
else if (version == '12.1(5)DC3')
  security_warning(0);
else if (version == '12.1(5)DC2')
  security_warning(0);
else if (version == '12.1(5)DC1')
  security_warning(0);
else if (version == '12.1(5)DC')
  security_warning(0);
else if (version == '12.1(4)DC3')
  security_warning(0);
else if (version == '12.1(4)DC2')
  security_warning(0);
else if (version == '12.1(3)DC2')
  security_warning(0);
else if (version == '12.1(3)DC1')
  security_warning(0);
else if (version == '12.1(3)DC')
  security_warning(0);
else if (version == '12.0(25)SX7')
  security_warning(0);
else if (version == '12.0(25)SX6e')
  security_warning(0);
else if (version == '12.0(25)SX6')
  security_warning(0);
else if (version == '12.0(25)SX5')
  security_warning(0);
else if (version == '12.0(25)SX4')
  security_warning(0);
else if (version == '12.0(25)SX3')
  security_warning(0);
else if (version == '12.0(25)SX2')
  security_warning(0);
else if (version == '12.0(25)SX1')
  security_warning(0);
else if (version == '12.0(25)SX')
  security_warning(0);
else if (version == '12.0(23)SX5')
  security_warning(0);
else if (version == '12.0(23)SX4')
  security_warning(0);
else if (version == '12.0(23)SX3')
  security_warning(0);
else if (version == '12.0(23)SX2')
  security_warning(0);
else if (version == '12.0(23)SX1')
  security_warning(0);
else if (version == '12.0(23)SX')
  security_warning(0);
else if (version == '12.0(21)SX1')
  security_warning(0);
else if (version == '12.0(21)SX')
  security_warning(0);
else if (version == '12.0(21)ST7')
  security_warning(0);
else if (version == '12.0(21)ST6')
  security_warning(0);
else if (version == '12.0(21)ST5')
  security_warning(0);
else if (version == '12.0(21)ST4')
  security_warning(0);
else if (version == '12.0(21)ST3a')
  security_warning(0);
else if (version == '12.0(21)ST3')
  security_warning(0);
else if (version == '12.0(21)ST2')
  security_warning(0);
else if (version == '12.0(21)ST1')
  security_warning(0);
else if (version == '12.0(21)ST')
  security_warning(0);
else if (version == '12.0(20)ST6')
  security_warning(0);
else if (version == '12.0(20)ST5')
  security_warning(0);
else if (version == '12.0(20)ST4')
  security_warning(0);
else if (version == '12.0(20)ST3')
  security_warning(0);
else if (version == '12.0(20)ST2')
  security_warning(0);
else if (version == '12.0(20)ST1')
  security_warning(0);
else if (version == '12.0(20)ST')
  security_warning(0);
else if (version == '12.0(19)ST6')
  security_warning(0);
else if (version == '12.0(19)ST3')
  security_warning(0);
else if (version == '12.0(19)ST2')
  security_warning(0);
else if (version == '12.0(19)ST1')
  security_warning(0);
else if (version == '12.0(19)ST')
  security_warning(0);
else if (version == '12.0(18)ST1')
  security_warning(0);
else if (version == '12.0(18)ST')
  security_warning(0);
else if (version == '12.0(17)ST8')
  security_warning(0);
else if (version == '12.0(17)ST7')
  security_warning(0);
else if (version == '12.0(17)ST6')
  security_warning(0);
else if (version == '12.0(17)ST5')
  security_warning(0);
else if (version == '12.0(17)ST4')
  security_warning(0);
else if (version == '12.0(17)ST3')
  security_warning(0);
else if (version == '12.0(17)ST2')
  security_warning(0);
else if (version == '12.0(17)ST1')
  security_warning(0);
else if (version == '12.0(17)ST')
  security_warning(0);
else if (version == '12.0(16)ST1')
  security_warning(0);
else if (version == '12.0(16)ST')
  security_warning(0);
else if (version == '12.0(14)ST3')
  security_warning(0);
else if (version == '12.0(14)ST2')
  security_warning(0);
else if (version == '12.0(14)ST1')
  security_warning(0);
else if (version == '12.0(14)ST')
  security_warning(0);
else if (version == '12.0(11)ST4')
  security_warning(0);
else if (version == '12.0(11)ST3')
  security_warning(0);
else if (version == '12.0(11)ST2')
  security_warning(0);
else if (version == '12.0(11)ST1')
  security_warning(0);
else if (version == '12.0(11)ST')
  security_warning(0);
else if (version == '12.0(10)ST2')
  security_warning(0);
else if (version == '12.0(10)ST1')
  security_warning(0);
else if (version == '12.0(10)ST')
  security_warning(0);
else if (version == '12.0(9)ST')
  security_warning(0);
else if (version == '12.0(19)SL4')
  security_warning(0);
else if (version == '12.0(19)SL3')
  security_warning(0);
else if (version == '12.0(19)SL2')
  security_warning(0);
else if (version == '12.0(25)S2')
  security_warning(0);
else if (version == '12.0(25)S1')
  security_warning(0);
else if (version == '12.0(25)S')
  security_warning(0);
else if (version == '12.0(24)S4')
  security_warning(0);
else if (version == '12.0(24)S3')
  security_warning(0);
else if (version == '12.0(24)S2')
  security_warning(0);
else if (version == '12.0(24)S1')
  security_warning(0);
else if (version == '12.0(24)S')
  security_warning(0);
else if (version == '12.0(23)S5')
  security_warning(0);
else if (version == '12.0(23)S4')
  security_warning(0);
else if (version == '12.0(23)S3b')
  security_warning(0);
else if (version == '12.0(23)S3a')
  security_warning(0);
else if (version == '12.0(23)S3')
  security_warning(0);
else if (version == '12.0(23)S2a')
  security_warning(0);
else if (version == '12.0(23)S2')
  security_warning(0);
else if (version == '12.0(23)S1')
  security_warning(0);
else if (version == '12.0(23)S')
  security_warning(0);
else if (version == '12.0(22)S6')
  security_warning(0);
else if (version == '12.0(22)S5a')
  security_warning(0);
else if (version == '12.0(22)S5')
  security_warning(0);
else if (version == '12.0(22)S4a')
  security_warning(0);
else if (version == '12.0(22)S4')
  security_warning(0);
else if (version == '12.0(22)S3c')
  security_warning(0);
else if (version == '12.0(22)S3b')
  security_warning(0);
else if (version == '12.0(22)S3a')
  security_warning(0);
else if (version == '12.0(22)S3')
  security_warning(0);
else if (version == '12.0(22)S2e')
  security_warning(0);
else if (version == '12.0(22)S2d')
  security_warning(0);
else if (version == '12.0(22)S2c')
  security_warning(0);
else if (version == '12.0(22)S2b')
  security_warning(0);
else if (version == '12.0(22)S2a')
  security_warning(0);
else if (version == '12.0(22)S2')
  security_warning(0);
else if (version == '12.0(22)S1')
  security_warning(0);
else if (version == '12.0(22)S')
  security_warning(0);
else
  exit(0, 'The host is not affected.');
