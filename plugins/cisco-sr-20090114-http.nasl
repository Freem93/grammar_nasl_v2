#TRUSTED 84bfe0021baf404578232dd58099373f5bebbf74eeba4ecf407641674b584093b7d9ea1859993633ed84802a63fa385b160ab1fdc4b0d9da2f1f6c60da9c82d2a2ebaab54443f4e7ed17c8147717faae113601aa896ed8f88fd99e91d459883c2b5348ab67b82fa69f7f166bbd6a5b7702972e684ebf72afe08eca2cb2d1a567ea1727a6a97c34880a924b406bd408b4ce0ee1607c028a3afd955bfab5edb72cd9a036a4d105784df40ab254e5f35cd509d61342b3a03e2394790788a7ffe283ff13393807380cfa622c35c7f47dd52fee233b1e86de66378d58d272e92f162b8a72ee28a9e5cf58b8595d9ec92e6bd1ef100ec29de851498f184ccb84763c931705e08846bd67b0e10912a6d8bb5b6a866452b5b547594eb435d7f9881faeb0255126207da6ca56acdfab2b9445de72bc5a1f931b8010e6f5fd99136c2a0dc3ea802585e1b2cdc383f00ddbd99938e46f9e0a5fd85fe7eb0c6d7d2b022211fb0dd4efcc280904bc086bb86a3f6e4428f3b314716fb6b7c70c52112891cfc89570af108d50d757c26053a740d31c6261079218e17296d35da10285c61426c7f36f5ef4837f745b8723411772fa8900fee1cf5c0fd8bce71ffa05c86acece74480749ecd6b374d04a1eb72d61dfeedc343a30166d6d43a65e92804902a52fc9b8f4732562f632b21fe81be9bdba760e9850a33ffdec9563b03f55e17c658feef4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17795);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2008-3821", "CVE-2009-0470");
 script_bugtraq_id(33260);
 script_osvdb_id(51393, 51394, 52318, 52319);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsi13344");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsr72301");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv05154");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsx49573");
 script_xref(name:"CISCO-SR", value:"cisco-sr-20090114-http");

 script_name(english:"Cisco IOS XSS and XSRF Vulnerabilities");
 script_summary(english:"Checks the version of Cisco IOS.");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"On June 19, 2009, Cisco released a security response for cross-site
scripting and cross-site request forgery vulnerabilities in the HTTP
server in IOS.

Exploitation of these vulnerabilities could result in attacker
supplied JavaScript or HTML being injected into web pages.  Further, a
remote attacker could trick a user into making a maliciously crafted
request.

This plugin checks if the appropriate fix for the advisory has been
installed.");
 # http://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20090114-http
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4528abd6");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500063");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory
cisco-sr-20090114-http.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/06/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/11");

 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2012-2014 Tenable Network Security, Inc.");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.2(0)TEST')
  flag++;
else if (version == '12.2(10)SBT112')
  flag++;
else if (version == '12.2(11)')
  flag++;
else if (version == '12.2(111)')
  flag++;
else if (version == '12.2(112)')
  flag++;
else if (version == '12.2(11)SBT112')
  flag++;
else if (version == '12.2(12g)TEST')
  flag++;
else if (version == '12.2(12h)SAVE')
  flag++;
else if (version == '12.2(12)SBT112')
  flag++;
else if (version == '12.2(14)')
  flag++;
else if (version == '12.2(17b)SXA')
  flag++;
else if (version == '12.2(17b)SXA1')
  flag++;
else if (version == '12.2(17b)SXA2')
  flag++;
else if (version == '12.2(17d)SXB')
  flag++;
else if (version == '12.2(17d)SXB1')
  flag++;
else if (version == '12.2(17d)SXB10')
  flag++;
else if (version == '12.2(17d)SXB11')
  flag++;
else if (version == '12.2(17d)SXB11a')
  flag++;
else if (version == '12.2(17d)SXB2')
  flag++;
else if (version == '12.2(17d)SXB3')
  flag++;
else if (version == '12.2(17d)SXB4')
  flag++;
else if (version == '12.2(17d)SXB5')
  flag++;
else if (version == '12.2(17d)SXB6')
  flag++;
else if (version == '12.2(17d)SXB7')
  flag++;
else if (version == '12.2(17d)SXB8')
  flag++;
else if (version == '12.2(17d)SXB9')
  flag++;
else if (version == '12.2(17r)SXB3')
  flag++;
else if (version == '12.2(18)SXD')
  flag++;
else if (version == '12.2(18)SXD1')
  flag++;
else if (version == '12.2(18)SXD2')
  flag++;
else if (version == '12.2(18)SXD3')
  flag++;
else if (version == '12.2(18)SXD4')
  flag++;
else if (version == '12.2(18)SXD5')
  flag++;
else if (version == '12.2(18)SXD6')
  flag++;
else if (version == '12.2(18)SXD7')
  flag++;
else if (version == '12.2(18)SXD7a')
  flag++;
else if (version == '12.2(18)SXD7b')
  flag++;
else if (version == '12.2(18)SXE')
  flag++;
else if (version == '12.2(18)SXE1')
  flag++;
else if (version == '12.2(18)SXE2')
  flag++;
else if (version == '12.2(18)SXE3')
  flag++;
else if (version == '12.2(18)SXE4')
  flag++;
else if (version == '12.2(18)SXE5')
  flag++;
else if (version == '12.2(18)SXE6')
  flag++;
else if (version == '12.2(18)SXE6a')
  flag++;
else if (version == '12.2(18)SXE6b')
  flag++;
else if (version == '12.2(18)SXF')
  flag++;
else if (version == '12.2(18)SXF1')
  flag++;
else if (version == '12.2(18)SXF10')
  flag++;
else if (version == '12.2(18)SXF10a')
  flag++;
else if (version == '12.2(18)SXF11')
  flag++;
else if (version == '12.2(18)SXF12')
  flag++;
else if (version == '12.2(18)SXF12a')
  flag++;
else if (version == '12.2(18)SXF13')
  flag++;
else if (version == '12.2(18)SXF13a')
  flag++;
else if (version == '12.2(18)SXF13b')
  flag++;
else if (version == '12.2(18)SXF14')
  flag++;
else if (version == '12.2(18)SXF15')
  flag++;
else if (version == '12.2(18)SXF15a')
  flag++;
else if (version == '12.2(18)SXF2')
  flag++;
else if (version == '12.2(18)SXF3')
  flag++;
else if (version == '12.2(18)SXF4')
  flag++;
else if (version == '12.2(18)SXF5')
  flag++;
else if (version == '12.2(18)SXF6')
  flag++;
else if (version == '12.2(18)SXF7')
  flag++;
else if (version == '12.2(18)SXF8')
  flag++;
else if (version == '12.2(18)SXF9')
  flag++;
else if (version == '12.2(18)ZYA')
  flag++;
else if (version == '12.2(18)ZYA1')
  flag++;
else if (version == '12.2(19)SAVE')
  flag++;
else if (version == '12.2(2)')
  flag++;
else if (version == '12.2(21)BASE')
  flag++;
else if (version == '12.2(25)SEA')
  flag++;
else if (version == '12.2(25)SEB')
  flag++;
else if (version == '12.2(25)SEB1')
  flag++;
else if (version == '12.2(25)SEB2')
  flag++;
else if (version == '12.2(25)SEB3')
  flag++;
else if (version == '12.2(25)SEB4')
  flag++;
else if (version == '12.2(25)SEC')
  flag++;
else if (version == '12.2(25)SEC1')
  flag++;
else if (version == '12.2(25)SEC2')
  flag++;
else if (version == '12.2(25)SED')
  flag++;
else if (version == '12.2(25)SED1')
  flag++;
else if (version == '12.2(25)SEE')
  flag++;
else if (version == '12.2(25)SEE1')
  flag++;
else if (version == '12.2(25)SEE2')
  flag++;
else if (version == '12.2(25)SEE3')
  flag++;
else if (version == '12.2(25)SEE4')
  flag++;
else if (version == '12.2(25)SEF')
  flag++;
else if (version == '12.2(25)SEF1')
  flag++;
else if (version == '12.2(25)SEF2')
  flag++;
else if (version == '12.2(25)SEF3')
  flag++;
else if (version == '12.2(25)SEG')
  flag++;
else if (version == '12.2(25)SEG1')
  flag++;
else if (version == '12.2(25)SEG2')
  flag++;
else if (version == '12.2(25)SEG3')
  flag++;
else if (version == '12.2(25)SEG4')
  flag++;
else if (version == '12.2(25)SEG5')
  flag++;
else if (version == '12.2(25)SEG6')
  flag++;
else if (version == '12.2(27)SBKA1')
  flag++;
else if (version == '12.2(27)SBKA2')
  flag++;
else if (version == '12.2(27)SBKA3')
  flag++;
else if (version == '12.2(27)SBKA4')
  flag++;
else if (version == '12.2(27)SBKA5')
  flag++;
else if (version == '12.2(27)SBKB')
  flag++;
else if (version == '12.2(27)SBKB1')
  flag++;
else if (version == '12.2(27)SBKB10')
  flag++;
else if (version == '12.2(27)SBKB2')
  flag++;
else if (version == '12.2(27)SBKB3')
  flag++;
else if (version == '12.2(27)SBKB4')
  flag++;
else if (version == '12.2(27)SBKB5')
  flag++;
else if (version == '12.2(27)SBKB6')
  flag++;
else if (version == '12.2(27)SBKB8')
  flag++;
else if (version == '12.2(27)SBKB9')
  flag++;
else if (version == '12.2(27)TEST2')
  flag++;
else if (version == '12.2(27)TST11')
  flag++;
else if (version == '12.2(27)TST8')
  flag++;
else if (version == '12.2(29)SVA2')
  flag++;
else if (version == '12.2(31)SBY')
  flag++;
else if (version == '12.2(31)SBY1')
  flag++;
else if (version == '12.2(31)SGA')
  flag++;
else if (version == '12.2(31)SGA1')
  flag++;
else if (version == '12.2(31)SGA2')
  flag++;
else if (version == '12.2(31)SGA3')
  flag++;
else if (version == '12.2(31)SGA4')
  flag++;
else if (version == '12.2(31)SGA5')
  flag++;
else if (version == '12.2(31)SGA6')
  flag++;
else if (version == '12.2(31)SGA7')
  flag++;
else if (version == '12.2(31)SGA8')
  flag++;
else if (version == '12.2(31)TST5')
  flag++;
else if (version == '12.2(33r)SRB')
  flag++;
else if (version == '12.2(33r)SRB1')
  flag++;
else if (version == '12.2(33r)SRB2')
  flag++;
else if (version == '12.2(33r)SRB3')
  flag++;
else if (version == '12.2(33r)XNB')
  flag++;
else if (version == '12.2(33r)XNC')
  flag++;
else if (version == '12.2(33)SRA')
  flag++;
else if (version == '12.2(33)SRA1')
  flag++;
else if (version == '12.2(33)SRA2')
  flag++;
else if (version == '12.2(33)SRA3')
  flag++;
else if (version == '12.2(33)SRA4')
  flag++;
else if (version == '12.2(33)SRA5')
  flag++;
else if (version == '12.2(33)SRA6')
  flag++;
else if (version == '12.2(33)SRA7')
  flag++;
else if (version == '12.2(33)SRB')
  flag++;
else if (version == '12.2(33)SRB1')
  flag++;
else if (version == '12.2(33)SRB2')
  flag++;
else if (version == '12.2(33)SRB3')
  flag++;
else if (version == '12.2(33)SRB4')
  flag++;
else if (version == '12.2(33)SRB5')
  flag++;
else if (version == '12.2(33)SXH')
  flag++;
else if (version == '12.2(33)SXH0a')
  flag++;
else if (version == '12.2(33)SXH1')
  flag++;
else if (version == '12.2(33)SXH2')
  flag++;
else if (version == '12.2(33)SXH2a')
  flag++;
else if (version == '12.2(33)SXH3')
  flag++;
else if (version == '12.2(33)SXH3a')
  flag++;
else if (version == '12.2(33)SXH4')
  flag++;
else if (version == '12.2(33)XNA')
  flag++;
else if (version == '12.2(33)XNA1')
  flag++;
else if (version == '12.2(33)XNA2')
  flag++;
else if (version == '12.2(33)XNB')
  flag++;
else if (version == '12.2(33)XNB1')
  flag++;
else if (version == '12.2(33)XNB2')
  flag++;
else if (version == '12.2(33)XNB2b')
  flag++;
else if (version == '12.2(3)SBT112')
  flag++;
else if (version == '12.2(4)')
  flag++;
else if (version == '12.2(4)SBT112')
  flag++;
else if (version == '12.2(5)SBT112')
  flag++;
else if (version == '12.2(6c)TEST')
  flag++;
else if (version == '12.2(73)TST')
  flag++;
else if (version == '12.2(7)SBT112')
  flag++;
else if (version == '12.2(8)')
  flag++;
else if (version == '12.2(8)SBT112')
  flag++;
else if (version == '12.2(8)TPC10a')
  flag++;
else if (version == '12.2(8)TPC10b')
  flag++;
else if (version == '12.2(8)TPC10c')
  flag++;
else if (version == '12.2(9)')
  flag++;
else if (version == '12.2(92)TST')
  flag++;
else if (version == '12.2(92)TST1')
  flag++;
else if (version == '12.2(92)TST2')
  flag++;
else if (version == '12.2(9909)TEST')
  flag++;
else if (version == '12.2(9999)SRA')
  flag++;
else if (version == '12.2(9999)SRA2')
  flag++;
else if (version == '12.2(99)TEST2')
  flag++;
else if (version == '12.2(9)SBT112')
  flag++;
else if (version == '12.3(1)')
  flag++;
else if (version == '12.3(10)')
  flag++;
else if (version == '12.3(10a)')
  flag++;
else if (version == '12.3(10a)M0')
  flag++;
else if (version == '12.3(10b)')
  flag++;
else if (version == '12.3(10c)')
  flag++;
else if (version == '12.3(10d)')
  flag++;
else if (version == '12.3(10e)')
  flag++;
else if (version == '12.3(10f)')
  flag++;
else if (version == '12.3(10r)')
  flag++;
else if (version == '12.3(11)JA')
  flag++;
else if (version == '12.3(11)JA1')
  flag++;
else if (version == '12.3(11)JA2')
  flag++;
else if (version == '12.3(11)JA3')
  flag++;
else if (version == '12.3(11)JA4')
  flag++;
else if (version == '12.3(11)JX')
  flag++;
else if (version == '12.3(11)JX1')
  flag++;
else if (version == '12.3(11r)T')
  flag++;
else if (version == '12.3(11r)T1')
  flag++;
else if (version == '12.3(11r)T2')
  flag++;
else if (version == '12.3(11)T')
  flag++;
else if (version == '12.3(11)T1')
  flag++;
else if (version == '12.3(11)T10')
  flag++;
else if (version == '12.3(11)T11')
  flag++;
else if (version == '12.3(11)T12')
  flag++;
else if (version == '12.3(11)T2')
  flag++;
else if (version == '12.3(11)T2a')
  flag++;
else if (version == '12.3(11)T3')
  flag++;
else if (version == '12.3(11)T4')
  flag++;
else if (version == '12.3(11)T5')
  flag++;
else if (version == '12.3(11)T6')
  flag++;
else if (version == '12.3(11)T7')
  flag++;
else if (version == '12.3(11)T8')
  flag++;
else if (version == '12.3(11)T9')
  flag++;
else if (version == '12.3(11)TO3')
  flag++;
else if (version == '12.3(11)XL')
  flag++;
else if (version == '12.3(11)XL1')
  flag++;
else if (version == '12.3(11)XL2')
  flag++;
else if (version == '12.3(11)XL3')
  flag++;
else if (version == '12.3(11)YF')
  flag++;
else if (version == '12.3(11)YF1')
  flag++;
else if (version == '12.3(11)YF2')
  flag++;
else if (version == '12.3(11)YF3')
  flag++;
else if (version == '12.3(11)YF4')
  flag++;
else if (version == '12.3(11)YJ')
  flag++;
else if (version == '12.3(11)YK')
  flag++;
else if (version == '12.3(11)YK1')
  flag++;
else if (version == '12.3(11)YK2')
  flag++;
else if (version == '12.3(11)YK3')
  flag++;
else if (version == '12.3(11)YL')
  flag++;
else if (version == '12.3(11)YL1')
  flag++;
else if (version == '12.3(11)YL2')
  flag++;
else if (version == '12.3(11)YN')
  flag++;
else if (version == '12.3(11)YR')
  flag++;
else if (version == '12.3(11)YR1')
  flag++;
else if (version == '12.3(11)YS')
  flag++;
else if (version == '12.3(11)YS1')
  flag++;
else if (version == '12.3(11)YS2')
  flag++;
else if (version == '12.3(11)YW')
  flag++;
else if (version == '12.3(11)YW1')
  flag++;
else if (version == '12.3(11)YW2')
  flag++;
else if (version == '12.3(11)YW3')
  flag++;
else if (version == '12.3(11)YZ')
  flag++;
else if (version == '12.3(11)YZ1')
  flag++;
else if (version == '12.3(11)YZ2')
  flag++;
else if (version == '12.3(11)ZB')
  flag++;
else if (version == '12.3(11)ZB1')
  flag++;
else if (version == '12.3(11)ZB2')
  flag++;
else if (version == '12.3(12)')
  flag++;
else if (version == '12.3(12a)')
  flag++;
else if (version == '12.3(12b)')
  flag++;
else if (version == '12.3(12c)')
  flag++;
else if (version == '12.3(12d)')
  flag++;
else if (version == '12.3(12e)')
  flag++;
else if (version == '12.3(12r)T')
  flag++;
else if (version == '12.3(12r)T1')
  flag++;
else if (version == '12.3(12r)T2')
  flag++;
else if (version == '12.3(13)')
  flag++;
else if (version == '12.3(13a)')
  flag++;
else if (version == '12.3(13a)BC')
  flag++;
else if (version == '12.3(13a)BC1')
  flag++;
else if (version == '12.3(13a)BC2')
  flag++;
else if (version == '12.3(13a)BC3')
  flag++;
else if (version == '12.3(13a)BC4')
  flag++;
else if (version == '12.3(13a)BC5')
  flag++;
else if (version == '12.3(13a)BC6')
  flag++;
else if (version == '12.3(13b)')
  flag++;
else if (version == '12.3(14r)T')
  flag++;
else if (version == '12.3(14r)T1')
  flag++;
else if (version == '12.3(14)T')
  flag++;
else if (version == '12.3(14)T1')
  flag++;
else if (version == '12.3(14)T2')
  flag++;
else if (version == '12.3(14)T3')
  flag++;
else if (version == '12.3(14)T4')
  flag++;
else if (version == '12.3(14)T5')
  flag++;
else if (version == '12.3(14)T6')
  flag++;
else if (version == '12.3(14)T7')
  flag++;
else if (version == '12.3(14)YM')
  flag++;
else if (version == '12.3(14)YM0707')
  flag++;
else if (version == '12.3(14)YM1')
  flag++;
else if (version == '12.3(14)YM10')
  flag++;
else if (version == '12.3(14)YM11')
  flag++;
else if (version == '12.3(14)YM12')
  flag++;
else if (version == '12.3(14)YM13')
  flag++;
else if (version == '12.3(14)YM2')
  flag++;
else if (version == '12.3(14)YM3')
  flag++;
else if (version == '12.3(14)YM4')
  flag++;
else if (version == '12.3(14)YM5')
  flag++;
else if (version == '12.3(14)YM6')
  flag++;
else if (version == '12.3(14)YM7')
  flag++;
else if (version == '12.3(14)YM8')
  flag++;
else if (version == '12.3(14)YM9')
  flag++;
else if (version == '12.3(14)YQ')
  flag++;
else if (version == '12.3(14)YQ051806')
  flag++;
else if (version == '12.3(14)YQ1')
  flag++;
else if (version == '12.3(14)YQ2')
  flag++;
else if (version == '12.3(14)YQ3')
  flag++;
else if (version == '12.3(14)YQ4')
  flag++;
else if (version == '12.3(14)YQ5')
  flag++;
else if (version == '12.3(14)YQ6')
  flag++;
else if (version == '12.3(14)YQ7')
  flag++;
else if (version == '12.3(14)YQ8')
  flag++;
else if (version == '12.3(14)YT')
  flag++;
else if (version == '12.3(14)YT1')
  flag++;
else if (version == '12.3(14)YU')
  flag++;
else if (version == '12.3(14)YU1')
  flag++;
else if (version == '12.3(14)YX')
  flag++;
else if (version == '12.3(14)YX1')
  flag++;
else if (version == '12.3(14)YX10')
  flag++;
else if (version == '12.3(14)YX11')
  flag++;
else if (version == '12.3(14)YX12')
  flag++;
else if (version == '12.3(14)YX13')
  flag++;
else if (version == '12.3(14)YX14')
  flag++;
else if (version == '12.3(14)YX15')
  flag++;
else if (version == '12.3(14)YX16')
  flag++;
else if (version == '12.3(14)YX17')
  flag++;
else if (version == '12.3(14)YX2')
  flag++;
else if (version == '12.3(14)YX3')
  flag++;
else if (version == '12.3(14)YX4')
  flag++;
else if (version == '12.3(14)YX5')
  flag++;
else if (version == '12.3(14)YX7')
  flag++;
else if (version == '12.3(14)YX8')
  flag++;
else if (version == '12.3(14)YX9')
  flag++;
else if (version == '12.3(15)')
  flag++;
else if (version == '12.3(15a)')
  flag++;
else if (version == '12.3(15b)')
  flag++;
else if (version == '12.3(16)')
  flag++;
else if (version == '12.3(16a)')
  flag++;
else if (version == '12.3(17)')
  flag++;
else if (version == '12.3(17a)')
  flag++;
else if (version == '12.3(17a)BC')
  flag++;
else if (version == '12.3(17a)BC1')
  flag++;
else if (version == '12.3(17a)BC2')
  flag++;
else if (version == '12.3(17b)')
  flag++;
else if (version == '12.3(17b)BC3')
  flag++;
else if (version == '12.3(17b)BC4')
  flag++;
else if (version == '12.3(17b)BC5')
  flag++;
else if (version == '12.3(17b)BC6')
  flag++;
else if (version == '12.3(17b)BC7')
  flag++;
else if (version == '12.3(17b)BC8')
  flag++;
else if (version == '12.3(17b)BC9')
  flag++;
else if (version == '12.3(17c)')
  flag++;
else if (version == '12.3(18)')
  flag++;
else if (version == '12.3(18a)')
  flag++;
else if (version == '12.3(18r)S1')
  flag++;
else if (version == '12.3(18r)S2')
  flag++;
else if (version == '12.3(18r)SX1')
  flag++;
else if (version == '12.3(19)')
  flag++;
else if (version == '12.3(19a)')
  flag++;
else if (version == '12.3(1a)')
  flag++;
else if (version == '12.3(1a)B')
  flag++;
else if (version == '12.3(1a)BW')
  flag++;
else if (version == '12.3(1)FIPS140')
  flag++;
else if (version == '12.3(1r)T')
  flag++;
else if (version == '12.3(1r)T1')
  flag++;
else if (version == '12.3(20)')
  flag++;
else if (version == '12.3(20a)')
  flag++;
else if (version == '12.3(21)')
  flag++;
else if (version == '12.3(21a)')
  flag++;
else if (version == '12.3(21a)BC1')
  flag++;
else if (version == '12.3(21a)BC2')
  flag++;
else if (version == '12.3(21a)BC3')
  flag++;
else if (version == '12.3(21a)BC4')
  flag++;
else if (version == '12.3(21a)BC5')
  flag++;
else if (version == '12.3(21a)BC6')
  flag++;
else if (version == '12.3(21a)BC7')
  flag++;
else if (version == '12.3(21a)BC8')
  flag++;
else if (version == '12.3(21a)BC9')
  flag++;
else if (version == '12.3(21b)')
  flag++;
else if (version == '12.3(21)BC')
  flag++;
else if (version == '12.3(21)BC20090622')
  flag++;
else if (version == '12.3(21)BC20090629')
  flag++;
else if (version == '12.3(21)BC20090706')
  flag++;
else if (version == '12.3(21)BC20090707')
  flag++;
else if (version == '12.3(21)BC20090728')
  flag++;
else if (version == '12.3(22)')
  flag++;
else if (version == '12.3(22a)')
  flag++;
else if (version == '12.3(23)')
  flag++;
else if (version == '12.3(23)BC')
  flag++;
else if (version == '12.3(23)BC080326')
  flag++;
else if (version == '12.3(23)BC080422')
  flag++;
else if (version == '12.3(23)BC080423')
  flag++;
else if (version == '12.3(23)BC1')
  flag++;
else if (version == '12.3(23)BC10')
  flag++;
else if (version == '12.3(23)BC2')
  flag++;
else if (version == '12.3(23)BC20081211')
  flag++;
else if (version == '12.3(23)BC20081213')
  flag++;
else if (version == '12.3(23)BC20081215')
  flag++;
else if (version == '12.3(23)BC20081217')
  flag++;
else if (version == '12.3(23)BC20081218')
  flag++;
else if (version == '12.3(23)BC20081224')
  flag++;
else if (version == '12.3(23)BC20081225')
  flag++;
else if (version == '12.3(23)BC20090101')
  flag++;
else if (version == '12.3(23)BC20090107')
  flag++;
else if (version == '12.3(23)BC20090108')
  flag++;
else if (version == '12.3(23)BC20090114')
  flag++;
else if (version == '12.3(23)BC20090121')
  flag++;
else if (version == '12.3(23)BC20090124')
  flag++;
else if (version == '12.3(23)BC20090128')
  flag++;
else if (version == '12.3(23)BC20090131')
  flag++;
else if (version == '12.3(23)BC20090204')
  flag++;
else if (version == '12.3(23)BC20090207')
  flag++;
else if (version == '12.3(23)BC20090211')
  flag++;
else if (version == '12.3(23)BC20090214')
  flag++;
else if (version == '12.3(23)BC20090218')
  flag++;
else if (version == '12.3(23)BC20090221')
  flag++;
else if (version == '12.3(23)BC20090225')
  flag++;
else if (version == '12.3(23)BC20090228')
  flag++;
else if (version == '12.3(23)BC20090304')
  flag++;
else if (version == '12.3(23)BC20090305')
  flag++;
else if (version == '12.3(23)BC20090311')
  flag++;
else if (version == '12.3(23)BC20090312')
  flag++;
else if (version == '12.3(23)BC20090313')
  flag++;
else if (version == '12.3(23)BC20090318')
  flag++;
else if (version == '12.3(23)BC20090321')
  flag++;
else if (version == '12.3(23)BC20090325')
  flag++;
else if (version == '12.3(23)BC20090408')
  flag++;
else if (version == '12.3(23)BC20090411')
  flag++;
else if (version == '12.3(23)BC20090415')
  flag++;
else if (version == '12.3(23)BC20090418')
  flag++;
else if (version == '12.3(23)BC20090422')
  flag++;
else if (version == '12.3(23)BC20090425')
  flag++;
else if (version == '12.3(23)BC20090429')
  flag++;
else if (version == '12.3(23)BC20090502')
  flag++;
else if (version == '12.3(23)BC20090506')
  flag++;
else if (version == '12.3(23)BC20090509')
  flag++;
else if (version == '12.3(23)BC20090513')
  flag++;
else if (version == '12.3(23)BC20090516')
  flag++;
else if (version == '12.3(23)BC20090520')
  flag++;
else if (version == '12.3(23)BC20090523')
  flag++;
else if (version == '12.3(23)BC20090527')
  flag++;
else if (version == '12.3(23)BC20090530')
  flag++;
else if (version == '12.3(23)BC20090606')
  flag++;
else if (version == '12.3(23)BC20090611')
  flag++;
else if (version == '12.3(23)BC20090620')
  flag++;
else if (version == '12.3(23)BC20090704')
  flag++;
else if (version == '12.3(23)BC20090718')
  flag++;
else if (version == '12.3(23)BC20090725')
  flag++;
else if (version == '12.3(23)BC20090801')
  flag++;
else if (version == '12.3(23)BC20090808')
  flag++;
else if (version == '12.3(23)BC20090815')
  flag++;
else if (version == '12.3(23)BC20090822')
  flag++;
else if (version == '12.3(23)BC20090829')
  flag++;
else if (version == '12.3(23)BC20090905')
  flag++;
else if (version == '12.3(23)BC20091114')
  flag++;
else if (version == '12.3(23)BC20091118')
  flag++;
else if (version == '12.3(23)BC20091212')
  flag++;
else if (version == '12.3(23)BC20110214')
  flag++;
else if (version == '12.3(23)BC20110217')
  flag++;
else if (version == '12.3(23)BC3')
  flag++;
else if (version == '12.3(23)BC4')
  flag++;
else if (version == '12.3(23)BC5')
  flag++;
else if (version == '12.3(23)BC6')
  flag++;
else if (version == '12.3(23)BC7')
  flag++;
else if (version == '12.3(23)BC8')
  flag++;
else if (version == '12.3(23)BC9')
  flag++;
else if (version == '12.3(24)')
  flag++;
else if (version == '12.3(24a)')
  flag++;
else if (version == '12.3(25)')
  flag++;
else if (version == '12.3(26)')
  flag++;
else if (version == '12.3(2)JA')
  flag++;
else if (version == '12.3(2)JA1')
  flag++;
else if (version == '12.3(2)JA2')
  flag++;
else if (version == '12.3(2)JA3')
  flag++;
else if (version == '12.3(2)JA4')
  flag++;
else if (version == '12.3(2)JA5')
  flag++;
else if (version == '12.3(2)JA6')
  flag++;
else if (version == '12.3(2)JK')
  flag++;
else if (version == '12.3(2)JK1')
  flag++;
else if (version == '12.3(2)JK2')
  flag++;
else if (version == '12.3(2)JK3')
  flag++;
else if (version == '12.3(2)JL')
  flag++;
else if (version == '12.3(2)JL1')
  flag++;
else if (version == '12.3(2)JL2')
  flag++;
else if (version == '12.3(2)JL3')
  flag++;
else if (version == '12.3(2)JL4')
  flag++;
else if (version == '12.3(2l)JK')
  flag++;
else if (version == '12.3(2l)JL')
  flag++;
else if (version == '12.3(2)T')
  flag++;
else if (version == '12.3(2)T1')
  flag++;
else if (version == '12.3(2)T2')
  flag++;
else if (version == '12.3(2)T3')
  flag++;
else if (version == '12.3(2)T4')
  flag++;
else if (version == '12.3(2)T5')
  flag++;
else if (version == '12.3(2)T6')
  flag++;
else if (version == '12.3(2)T7')
  flag++;
else if (version == '12.3(2)T8')
  flag++;
else if (version == '12.3(2)T9')
  flag++;
else if (version == '12.3(2)XA')
  flag++;
else if (version == '12.3(2)XA1')
  flag++;
else if (version == '12.3(2)XA2')
  flag++;
else if (version == '12.3(2)XA3')
  flag++;
else if (version == '12.3(2)XA4')
  flag++;
else if (version == '12.3(2)XA5')
  flag++;
else if (version == '12.3(2)XA6')
  flag++;
else if (version == '12.3(2)XA7')
  flag++;
else if (version == '12.3(2)XC')
  flag++;
else if (version == '12.3(2)XC1')
  flag++;
else if (version == '12.3(2)XC2')
  flag++;
else if (version == '12.3(2)XC3')
  flag++;
else if (version == '12.3(2)XC4')
  flag++;
else if (version == '12.3(2)XC5')
  flag++;
else if (version == '12.3(2)XE')
  flag++;
else if (version == '12.3(2)XE1')
  flag++;
else if (version == '12.3(2)XE2')
  flag++;
else if (version == '12.3(2)XE3')
  flag++;
else if (version == '12.3(2)XE4')
  flag++;
else if (version == '12.3(2)XE5')
  flag++;
else if (version == '12.3(2)XF')
  flag++;
else if (version == '12.3(2)XT')
  flag++;
else if (version == '12.3(2)XT1')
  flag++;
else if (version == '12.3(2)XT2')
  flag++;
else if (version == '12.3(2)XT3')
  flag++;
else if (version == '12.3(2)XZ')
  flag++;
else if (version == '12.3(2)XZ1')
  flag++;
else if (version == '12.3(2)XZ2')
  flag++;
else if (version == '12.3(3)')
  flag++;
else if (version == '12.3(3a)')
  flag++;
else if (version == '12.3(3b)')
  flag++;
else if (version == '12.3(3)B')
  flag++;
else if (version == '12.3(3)B1')
  flag++;
else if (version == '12.3(3c)')
  flag++;
else if (version == '12.3(3d)')
  flag++;
else if (version == '12.3(3e)')
  flag++;
else if (version == '12.3(3f)')
  flag++;
else if (version == '12.3(3f)SAVE')
  flag++;
else if (version == '12.3(3g)')
  flag++;
else if (version == '12.3(3h)')
  flag++;
else if (version == '12.3(3i)')
  flag++;
else if (version == '12.3(4)INF')
  flag++;
else if (version == '12.3(4)JA')
  flag++;
else if (version == '12.3(4)JA1')
  flag++;
else if (version == '12.3(4)JA2')
  flag++;
else if (version == '12.3(4r)T')
  flag++;
else if (version == '12.3(4r)T1')
  flag++;
else if (version == '12.3(4r)T2')
  flag++;
else if (version == '12.3(4r)T3')
  flag++;
else if (version == '12.3(4r)T4')
  flag++;
else if (version == '12.3(4r)XD')
  flag++;
else if (version == '12.3(4)T')
  flag++;
else if (version == '12.3(4)T1')
  flag++;
else if (version == '12.3(4)T10')
  flag++;
else if (version == '12.3(4)T11')
  flag++;
else if (version == '12.3(4)T12')
  flag++;
else if (version == '12.3(4)T2')
  flag++;
else if (version == '12.3(4)T2a')
  flag++;
else if (version == '12.3(4)T3')
  flag++;
else if (version == '12.3(4)T4')
  flag++;
else if (version == '12.3(4)T5')
  flag++;
else if (version == '12.3(4)T6')
  flag++;
else if (version == '12.3(4)T7')
  flag++;
else if (version == '12.3(4)T8')
  flag++;
else if (version == '12.3(4)T9')
  flag++;
else if (version == '12.3(4)TPC11a')
  flag++;
else if (version == '12.3(4)TPC11b')
  flag++;
else if (version == '12.3(4)XD')
  flag++;
else if (version == '12.3(4)XD1')
  flag++;
else if (version == '12.3(4)XD2')
  flag++;
else if (version == '12.3(4)XD3')
  flag++;
else if (version == '12.3(4)XD4')
  flag++;
else if (version == '12.3(4)XG')
  flag++;
else if (version == '12.3(4)XG1')
  flag++;
else if (version == '12.3(4)XG2')
  flag++;
else if (version == '12.3(4)XG3')
  flag++;
else if (version == '12.3(4)XG4')
  flag++;
else if (version == '12.3(4)XG5')
  flag++;
else if (version == '12.3(4)XN')
  flag++;
else if (version == '12.3(4)XN1')
  flag++;
else if (version == '12.3(4)XN2')
  flag++;
else if (version == '12.3(4)YE')
  flag++;
else if (version == '12.3(4)YE1')
  flag++;
else if (version == '12.3(5)')
  flag++;
else if (version == '12.3(5a)')
  flag++;
else if (version == '12.3(5a)B')
  flag++;
else if (version == '12.3(5a)B0a')
  flag++;
else if (version == '12.3(5a)B1')
  flag++;
else if (version == '12.3(5a)B2')
  flag++;
else if (version == '12.3(5a)B3')
  flag++;
else if (version == '12.3(5a)B4')
  flag++;
else if (version == '12.3(5a)B5')
  flag++;
else if (version == '12.3(5b)')
  flag++;
else if (version == '12.3(5c)')
  flag++;
else if (version == '12.3(5d)')
  flag++;
else if (version == '12.3(5e)')
  flag++;
else if (version == '12.3(5f)')
  flag++;
else if (version == '12.3(6)')
  flag++;
else if (version == '12.3(6a)')
  flag++;
else if (version == '12.3(6b)')
  flag++;
else if (version == '12.3(6c)')
  flag++;
else if (version == '12.3(6d)')
  flag++;
else if (version == '12.3(6e)')
  flag++;
else if (version == '12.3(6f)')
  flag++;
else if (version == '12.3(6r)')
  flag++;
else if (version == '12.3(7)JA')
  flag++;
else if (version == '12.3(7)JA1')
  flag++;
else if (version == '12.3(7)JA2')
  flag++;
else if (version == '12.3(7)JA3')
  flag++;
else if (version == '12.3(7)JA4')
  flag++;
else if (version == '12.3(7)JA5')
  flag++;
else if (version == '12.3(7)JX')
  flag++;
else if (version == '12.3(7)JX1')
  flag++;
else if (version == '12.3(7)JX10')
  flag++;
else if (version == '12.3(7)JX11')
  flag++;
else if (version == '12.3(7)JX12')
  flag++;
else if (version == '12.3(7)JX2')
  flag++;
else if (version == '12.3(7)JX3')
  flag++;
else if (version == '12.3(7)JX4')
  flag++;
else if (version == '12.3(7)JX5')
  flag++;
else if (version == '12.3(7)JX6')
  flag++;
else if (version == '12.3(7)JX7')
  flag++;
else if (version == '12.3(7)JX8')
  flag++;
else if (version == '12.3(7)JX9')
  flag++;
else if (version == '12.3(7r)T')
  flag++;
else if (version == '12.3(7r)T1')
  flag++;
else if (version == '12.3(7r)T2')
  flag++;
else if (version == '12.3(7)T')
  flag++;
else if (version == '12.3(7)T1')
  flag++;
else if (version == '12.3(7)T10')
  flag++;
else if (version == '12.3(7)T11')
  flag++;
else if (version == '12.3(7)T12')
  flag++;
else if (version == '12.3(7)T2')
  flag++;
else if (version == '12.3(7)T3')
  flag++;
else if (version == '12.3(7)T4')
  flag++;
else if (version == '12.3(7)T5')
  flag++;
else if (version == '12.3(7)T6')
  flag++;
else if (version == '12.3(7)T7')
  flag++;
else if (version == '12.3(7)T8')
  flag++;
else if (version == '12.3(7)T9')
  flag++;
else if (version == '12.3(7)XI')
  flag++;
else if (version == '12.3(7)XI1')
  flag++;
else if (version == '12.3(7)XI10')
  flag++;
else if (version == '12.3(7)XI10a')
  flag++;
else if (version == '12.3(7)XI10b')
  flag++;
else if (version == '12.3(7)XI1a')
  flag++;
else if (version == '12.3(7)XI1b')
  flag++;
else if (version == '12.3(7)XI1c')
  flag++;
else if (version == '12.3(7)XI2')
  flag++;
else if (version == '12.3(7)XI2a')
  flag++;
else if (version == '12.3(7)XI2b')
  flag++;
else if (version == '12.3(7)XI2c')
  flag++;
else if (version == '12.3(7)XI3')
  flag++;
else if (version == '12.3(7)XI3a')
  flag++;
else if (version == '12.3(7)XI3b')
  flag++;
else if (version == '12.3(7)XI3c')
  flag++;
else if (version == '12.3(7)XI3d')
  flag++;
else if (version == '12.3(7)XI3e')
  flag++;
else if (version == '12.3(7)XI4')
  flag++;
else if (version == '12.3(7)XI5')
  flag++;
else if (version == '12.3(7)XI6')
  flag++;
else if (version == '12.3(7)XI7')
  flag++;
else if (version == '12.3(7)XI7a')
  flag++;
else if (version == '12.3(7)XI7b')
  flag++;
else if (version == '12.3(7)XI7c')
  flag++;
else if (version == '12.3(7)XI7d')
  flag++;
else if (version == '12.3(7)XI7e')
  flag++;
else if (version == '12.3(7)XI7f')
  flag++;
else if (version == '12.3(7)XI8')
  flag++;
else if (version == '12.3(7)XI8a')
  flag++;
else if (version == '12.3(7)XI8b')
  flag++;
else if (version == '12.3(7)XI8c')
  flag++;
else if (version == '12.3(7)XI8d')
  flag++;
else if (version == '12.3(7)XI8e')
  flag++;
else if (version == '12.3(7)XI8f')
  flag++;
else if (version == '12.3(7)XI8g')
  flag++;
else if (version == '12.3(7)XI9')
  flag++;
else if (version == '12.3(7)XJ')
  flag++;
else if (version == '12.3(7)XJ1')
  flag++;
else if (version == '12.3(7)XJ2')
  flag++;
else if (version == '12.3(7)XL')
  flag++;
else if (version == '12.3(7)XM')
  flag++;
else if (version == '12.3(7)XR')
  flag++;
else if (version == '12.3(7)XR1')
  flag++;
else if (version == '12.3(7)XR2')
  flag++;
else if (version == '12.3(7)XR3')
  flag++;
else if (version == '12.3(7)XR4')
  flag++;
else if (version == '12.3(7)XR5')
  flag++;
else if (version == '12.3(7)XR6')
  flag++;
else if (version == '12.3(7)XR7')
  flag++;
else if (version == '12.3(7)XS')
  flag++;
else if (version == '12.3(7)XS1')
  flag++;
else if (version == '12.3(7)XS2')
  flag++;
else if (version == '12.3(7)YB')
  flag++;
else if (version == '12.3(7)YB1')
  flag++;
else if (version == '12.3(8)JA')
  flag++;
else if (version == '12.3(8)JA1')
  flag++;
else if (version == '12.3(8)JA2')
  flag++;
else if (version == '12.3(8)JEA')
  flag++;
else if (version == '12.3(8)JEA1')
  flag++;
else if (version == '12.3(8)JEA2')
  flag++;
else if (version == '12.3(8)JEA3')
  flag++;
else if (version == '12.3(8)JEB')
  flag++;
else if (version == '12.3(8)JEB1')
  flag++;
else if (version == '12.3(8)JEC')
  flag++;
else if (version == '12.3(8)JEC1')
  flag++;
else if (version == '12.3(8)JEC2')
  flag++;
else if (version == '12.3(8)JEC3')
  flag++;
else if (version == '12.3(8)JED')
  flag++;
else if (version == '12.3(8)JED1')
  flag++;
else if (version == '12.3(8)JEE')
  flag++;
else if (version == '12.3(8)JK')
  flag++;
else if (version == '12.3(8)JK1')
  flag++;
else if (version == '12.3(8r)T')
  flag++;
else if (version == '12.3(8r)T1')
  flag++;
else if (version == '12.3(8r)T10')
  flag++;
else if (version == '12.3(8r)T2')
  flag++;
else if (version == '12.3(8r)T3')
  flag++;
else if (version == '12.3(8r)T4')
  flag++;
else if (version == '12.3(8r)T5')
  flag++;
else if (version == '12.3(8r)T6')
  flag++;
else if (version == '12.3(8r)T7')
  flag++;
else if (version == '12.3(8r)T8')
  flag++;
else if (version == '12.3(8r)T9')
  flag++;
else if (version == '12.3(8r)YH')
  flag++;
else if (version == '12.3(8r)YH1')
  flag++;
else if (version == '12.3(8r)YH10')
  flag++;
else if (version == '12.3(8r)YH11')
  flag++;
else if (version == '12.3(8r)YH12')
  flag++;
else if (version == '12.3(8r)YH13')
  flag++;
else if (version == '12.3(8r)YH2')
  flag++;
else if (version == '12.3(8r)YH3')
  flag++;
else if (version == '12.3(8r)YH4')
  flag++;
else if (version == '12.3(8r)YH5')
  flag++;
else if (version == '12.3(8r)YH6')
  flag++;
else if (version == '12.3(8r)YH7')
  flag++;
else if (version == '12.3(8r)YH8')
  flag++;
else if (version == '12.3(8r)YH9')
  flag++;
else if (version == '12.3(8)T')
  flag++;
else if (version == '12.3(8)T0a')
  flag++;
else if (version == '12.3(8)T1')
  flag++;
else if (version == '12.3(8)T10')
  flag++;
else if (version == '12.3(8)T11')
  flag++;
else if (version == '12.3(8)T2')
  flag++;
else if (version == '12.3(8)T3')
  flag++;
else if (version == '12.3(8)T4')
  flag++;
else if (version == '12.3(8)T5')
  flag++;
else if (version == '12.3(8)T6')
  flag++;
else if (version == '12.3(8)T7')
  flag++;
else if (version == '12.3(8)T8')
  flag++;
else if (version == '12.3(8)T9')
  flag++;
else if (version == '12.3(8)XU')
  flag++;
else if (version == '12.3(8)XU1')
  flag++;
else if (version == '12.3(8)XU2')
  flag++;
else if (version == '12.3(8)XU3')
  flag++;
else if (version == '12.3(8)XU4')
  flag++;
else if (version == '12.3(8)XU5')
  flag++;
else if (version == '12.3(8)XW')
  flag++;
else if (version == '12.3(8)XW1')
  flag++;
else if (version == '12.3(8)XW1a')
  flag++;
else if (version == '12.3(8)XW1b')
  flag++;
else if (version == '12.3(8)XW2')
  flag++;
else if (version == '12.3(8)XW3')
  flag++;
else if (version == '12.3(8)XX')
  flag++;
else if (version == '12.3(8)XX1')
  flag++;
else if (version == '12.3(8)XX2')
  flag++;
else if (version == '12.3(8)XX2a')
  flag++;
else if (version == '12.3(8)XX2b')
  flag++;
else if (version == '12.3(8)XX2c')
  flag++;
else if (version == '12.3(8)XX2d')
  flag++;
else if (version == '12.3(8)XX2e')
  flag++;
else if (version == '12.3(8)XY')
  flag++;
else if (version == '12.3(8)XY1')
  flag++;
else if (version == '12.3(8)XY2')
  flag++;
else if (version == '12.3(8)XY3')
  flag++;
else if (version == '12.3(8)XY4')
  flag++;
else if (version == '12.3(8)XY5')
  flag++;
else if (version == '12.3(8)XY6')
  flag++;
else if (version == '12.3(8)XY7')
  flag++;
else if (version == '12.3(8)YA')
  flag++;
else if (version == '12.3(8)YA1')
  flag++;
else if (version == '12.3(8)YC')
  flag++;
else if (version == '12.3(8)YC1')
  flag++;
else if (version == '12.3(8)YC2')
  flag++;
else if (version == '12.3(8)YC3')
  flag++;
else if (version == '12.3(8)YD')
  flag++;
else if (version == '12.3(8)YD1')
  flag++;
else if (version == '12.3(8)YG')
  flag++;
else if (version == '12.3(8)YG1')
  flag++;
else if (version == '12.3(8)YG2')
  flag++;
else if (version == '12.3(8)YG3')
  flag++;
else if (version == '12.3(8)YG4')
  flag++;
else if (version == '12.3(8)YG5')
  flag++;
else if (version == '12.3(8)YG6')
  flag++;
else if (version == '12.3(8)YG7')
  flag++;
else if (version == '12.3(8)YH')
  flag++;
else if (version == '12.3(8)YI')
  flag++;
else if (version == '12.3(8)YI1')
  flag++;
else if (version == '12.3(8)YI2')
  flag++;
else if (version == '12.3(8)YI3')
  flag++;
else if (version == '12.3(8)ZA')
  flag++;
else if (version == '12.3(8)ZA1')
  flag++;
else if (version == '12.3(9)')
  flag++;
else if (version == '12.3(99)T')
  flag++;
else if (version == '12.3(9a)')
  flag++;
else if (version == '12.3(9a)BC')
  flag++;
else if (version == '12.3(9a)BC1')
  flag++;
else if (version == '12.3(9a)BC2')
  flag++;
else if (version == '12.3(9a)BC3')
  flag++;
else if (version == '12.3(9a)BC4')
  flag++;
else if (version == '12.3(9a)BC5')
  flag++;
else if (version == '12.3(9a)BC6')
  flag++;
else if (version == '12.3(9a)BC7')
  flag++;
else if (version == '12.3(9a)BC8')
  flag++;
else if (version == '12.3(9a)BC9')
  flag++;
else if (version == '12.3(9b)')
  flag++;
else if (version == '12.3(9c)')
  flag++;
else if (version == '12.3(9d)')
  flag++;
else if (version == '12.3(9e)')
  flag++;
else if (version == '12.3(9)M0')
  flag++;
else if (version == '12.3(9)M1')
  flag++;
else if (version == '12.3(9r)T')
  flag++;
else if (version == '12.4(1)')
  flag++;
else if (version == '12.4(10)')
  flag++;
else if (version == '12.4(10a)')
  flag++;
else if (version == '12.4(10b)')
  flag++;
else if (version == '12.4(10b)JA')
  flag++;
else if (version == '12.4(10b)JA1')
  flag++;
else if (version == '12.4(10b)JA2')
  flag++;
else if (version == '12.4(10b)JA3')
  flag++;
else if (version == '12.4(10b)JA4')
  flag++;
else if (version == '12.4(10b)JDA')
  flag++;
else if (version == '12.4(10b)JDA1')
  flag++;
else if (version == '12.4(10b)JDA2')
  flag++;
else if (version == '12.4(10b)JDD')
  flag++;
else if (version == '12.4(10b)JDE')
  flag++;
else if (version == '12.4(10b)JX')
  flag++;
else if (version == '12.4(10c)')
  flag++;
else if (version == '12.4(113a)TST1')
  flag++;
else if (version == '12.4(113a)TST2')
  flag++;
else if (version == '12.4(11)MD')
  flag++;
else if (version == '12.4(11)MD1')
  flag++;
else if (version == '12.4(11)MD10')
  flag++;
else if (version == '12.4(11)MD2')
  flag++;
else if (version == '12.4(11)MD3')
  flag++;
else if (version == '12.4(11)MD4')
  flag++;
else if (version == '12.4(11)MD5')
  flag++;
else if (version == '12.4(11)MD6')
  flag++;
else if (version == '12.4(11)MD7')
  flag++;
else if (version == '12.4(11)MD8')
  flag++;
else if (version == '12.4(11)MD9')
  flag++;
else if (version == '12.4(11)MR')
  flag++;
else if (version == '12.4(11r)MC')
  flag++;
else if (version == '12.4(11r)MC1')
  flag++;
else if (version == '12.4(11r)MC2')
  flag++;
else if (version == '12.4(11r)MD')
  flag++;
else if (version == '12.4(11r)XW')
  flag++;
else if (version == '12.4(11r)XW3')
  flag++;
else if (version == '12.4(11)SW')
  flag++;
else if (version == '12.4(11)SW1')
  flag++;
else if (version == '12.4(11)SW2')
  flag++;
else if (version == '12.4(11)SW3')
  flag++;
else if (version == '12.4(11)T')
  flag++;
else if (version == '12.4(11)T1')
  flag++;
else if (version == '12.4(11)T2')
  flag++;
else if (version == '12.4(11)T3')
  flag++;
else if (version == '12.4(11)T4')
  flag++;
else if (version == '12.4(11)XJ')
  flag++;
else if (version == '12.4(11)XJ1')
  flag++;
else if (version == '12.4(11)XJ2')
  flag++;
else if (version == '12.4(11)XJ3')
  flag++;
else if (version == '12.4(11)XJ4')
  flag++;
else if (version == '12.4(11)XJ5')
  flag++;
else if (version == '12.4(11)XJ6')
  flag++;
else if (version == '12.4(11)XV')
  flag++;
else if (version == '12.4(11)XV1')
  flag++;
else if (version == '12.4(11)XW')
  flag++;
else if (version == '12.4(11)XW1')
  flag++;
else if (version == '12.4(11)XW10')
  flag++;
else if (version == '12.4(11)XW2')
  flag++;
else if (version == '12.4(11)XW3')
  flag++;
else if (version == '12.4(11)XW4')
  flag++;
else if (version == '12.4(11)XW5')
  flag++;
else if (version == '12.4(11)XW6')
  flag++;
else if (version == '12.4(11)XW7')
  flag++;
else if (version == '12.4(11)XW8')
  flag++;
else if (version == '12.4(11)XW9')
  flag++;
else if (version == '12.4(12)')
  flag++;
else if (version == '12.4(123e)TST')
  flag++;
else if (version == '12.4(123g)TST')
  flag++;
else if (version == '12.4(12a)')
  flag++;
else if (version == '12.4(12b)')
  flag++;
else if (version == '12.4(12c)')
  flag++;
else if (version == '12.4(12)MR')
  flag++;
else if (version == '12.4(12)MR1')
  flag++;
else if (version == '12.4(12)MR2')
  flag++;
else if (version == '12.4(13)')
  flag++;
else if (version == '12.4(13a)')
  flag++;
else if (version == '12.4(13b)')
  flag++;
else if (version == '12.4(13c)')
  flag++;
else if (version == '12.4(13d)')
  flag++;
else if (version == '12.4(13d)JA')
  flag++;
else if (version == '12.4(13e)')
  flag++;
else if (version == '12.4(13f)')
  flag++;
else if (version == '12.4(13r)T')
  flag++;
else if (version == '12.4(13r)T1')
  flag++;
else if (version == '12.4(13r)T10')
  flag++;
else if (version == '12.4(13r)T11')
  flag++;
else if (version == '12.4(13r)T12')
  flag++;
else if (version == '12.4(13r)T13')
  flag++;
else if (version == '12.4(13r)T14')
  flag++;
else if (version == '12.4(13r)T15')
  flag++;
else if (version == '12.4(13r)T16')
  flag++;
else if (version == '12.4(13r)T2')
  flag++;
else if (version == '12.4(13r)T3')
  flag++;
else if (version == '12.4(13r)T4')
  flag++;
else if (version == '12.4(13r)T5')
  flag++;
else if (version == '12.4(13r)T6')
  flag++;
else if (version == '12.4(13r)T7')
  flag++;
else if (version == '12.4(13r)T8')
  flag++;
else if (version == '12.4(13r)T9')
  flag++;
else if (version == '12.4(14r)')
  flag++;
else if (version == '12.4(14r)T')
  flag++;
else if (version == '12.4(14)XK')
  flag++;
else if (version == '12.4(15)MD')
  flag++;
else if (version == '12.4(15)MD1')
  flag++;
else if (version == '12.4(15)MD1a')
  flag++;
else if (version == '12.4(15)MD2')
  flag++;
else if (version == '12.4(15)MD3')
  flag++;
else if (version == '12.4(15)MD4')
  flag++;
else if (version == '12.4(15)MD5')
  flag++;
else if (version == '12.4(15r)T')
  flag++;
else if (version == '12.4(15r)T1')
  flag++;
else if (version == '12.4(15r)XQ')
  flag++;
else if (version == '12.4(15r)XQ1')
  flag++;
else if (version == '12.4(15r)XZ')
  flag++;
else if (version == '12.4(15r)XZ1')
  flag++;
else if (version == '12.4(15r)XZ2')
  flag++;
else if (version == '12.4(15r)XZ3')
  flag++;
else if (version == '12.4(15r)XZ4')
  flag++;
else if (version == '12.4(15r)XZ5')
  flag++;
else if (version == '12.4(15)SW')
  flag++;
else if (version == '12.4(15)SW1')
  flag++;
else if (version == '12.4(15)SW2')
  flag++;
else if (version == '12.4(15)SW3')
  flag++;
else if (version == '12.4(15)SW4')
  flag++;
else if (version == '12.4(15)SW5')
  flag++;
else if (version == '12.4(15)SW6')
  flag++;
else if (version == '12.4(15)SW7')
  flag++;
else if (version == '12.4(15)SW8')
  flag++;
else if (version == '12.4(15)SW8a')
  flag++;
else if (version == '12.4(15)T')
  flag++;
else if (version == '12.4(15)T1')
  flag++;
else if (version == '12.4(15)T10')
  flag++;
else if (version == '12.4(15)T11')
  flag++;
else if (version == '12.4(15)T12')
  flag++;
else if (version == '12.4(15)T13')
  flag++;
else if (version == '12.4(15)T13b')
  flag++;
else if (version == '12.4(15)T14')
  flag++;
else if (version == '12.4(15)T15')
  flag++;
else if (version == '12.4(15)T16')
  flag++;
else if (version == '12.4(15)T17')
  flag++;
else if (version == '12.4(15)T2')
  flag++;
else if (version == '12.4(15)T3')
  flag++;
else if (version == '12.4(15)T4')
  flag++;
else if (version == '12.4(15)T5')
  flag++;
else if (version == '12.4(15)T6')
  flag++;
else if (version == '12.4(15)T6a')
  flag++;
else if (version == '12.4(15)T7')
  flag++;
else if (version == '12.4(15)T8')
  flag++;
else if (version == '12.4(15)T9')
  flag++;
else if (version == '12.4(15)XF')
  flag++;
else if (version == '12.4(15)XL')
  flag++;
else if (version == '12.4(15)XL1')
  flag++;
else if (version == '12.4(15)XL2')
  flag++;
else if (version == '12.4(15)XL3')
  flag++;
else if (version == '12.4(15)XL4')
  flag++;
else if (version == '12.4(15)XL5')
  flag++;
else if (version == '12.4(15)XM')
  flag++;
else if (version == '12.4(15)XM1')
  flag++;
else if (version == '12.4(15)XM2')
  flag++;
else if (version == '12.4(15)XM3')
  flag++;
else if (version == '12.4(15)XQ')
  flag++;
else if (version == '12.4(15)XQ1')
  flag++;
else if (version == '12.4(15)XQ2')
  flag++;
else if (version == '12.4(15)XQ2a')
  flag++;
else if (version == '12.4(15)XQ2b')
  flag++;
else if (version == '12.4(15)XQ2c')
  flag++;
else if (version == '12.4(15)XQ2d')
  flag++;
else if (version == '12.4(15)XQ3')
  flag++;
else if (version == '12.4(15)XQ4')
  flag++;
else if (version == '12.4(15)XQ5')
  flag++;
else if (version == '12.4(15)XQ6')
  flag++;
else if (version == '12.4(15)XQ7')
  flag++;
else if (version == '12.4(15)XQ8')
  flag++;
else if (version == '12.4(15)XR')
  flag++;
else if (version == '12.4(15)XR1')
  flag++;
else if (version == '12.4(15)XR10')
  flag++;
else if (version == '12.4(15)XR2')
  flag++;
else if (version == '12.4(15)XR3')
  flag++;
else if (version == '12.4(15)XR4')
  flag++;
else if (version == '12.4(15)XR5')
  flag++;
else if (version == '12.4(15)XR6')
  flag++;
else if (version == '12.4(15)XR7')
  flag++;
else if (version == '12.4(15)XR8')
  flag++;
else if (version == '12.4(15)XR9')
  flag++;
else if (version == '12.4(15)XY')
  flag++;
else if (version == '12.4(15)XY1')
  flag++;
else if (version == '12.4(15)XY2')
  flag++;
else if (version == '12.4(15)XY3')
  flag++;
else if (version == '12.4(15)XY4')
  flag++;
else if (version == '12.4(15)XY5')
  flag++;
else if (version == '12.4(15)XZ')
  flag++;
else if (version == '12.4(15)XZ1')
  flag++;
else if (version == '12.4(15)XZ2')
  flag++;
else if (version == '12.4(16)')
  flag++;
else if (version == '12.4(16a)')
  flag++;
else if (version == '12.4(16b)')
  flag++;
else if (version == '12.4(16b)JA')
  flag++;
else if (version == '12.4(16)MR')
  flag++;
else if (version == '12.4(16)MR1')
  flag++;
else if (version == '12.4(16)MR2')
  flag++;
else if (version == '12.4(16)TRY1')
  flag++;
else if (version == '12.4(17)')
  flag++;
else if (version == '12.4(17a)')
  flag++;
else if (version == '12.4(17b)')
  flag++;
else if (version == '12.4(18)')
  flag++;
else if (version == '12.4(18a)')
  flag++;
else if (version == '12.4(18a)JA')
  flag++;
else if (version == '12.4(18a)JA1')
  flag++;
else if (version == '12.4(18b)')
  flag++;
else if (version == '12.4(18c)')
  flag++;
else if (version == '12.4(18d)')
  flag++;
else if (version == '12.4(19)')
  flag++;
else if (version == '12.4(19a)')
  flag++;
else if (version == '12.4(19b)')
  flag++;
else if (version == '12.4(19)MR')
  flag++;
else if (version == '12.4(19)MR1')
  flag++;
else if (version == '12.4(19)MR2')
  flag++;
else if (version == '12.4(19)MR3')
  flag++;
else if (version == '12.4(1a)')
  flag++;
else if (version == '12.4(1b)')
  flag++;
else if (version == '12.4(1c)')
  flag++;
else if (version == '12.4(1r)')
  flag++;
else if (version == '12.4(20)MR')
  flag++;
else if (version == '12.4(20)MR1')
  flag++;
else if (version == '12.4(20)MR2')
  flag++;
else if (version == '12.4(20)MRA')
  flag++;
else if (version == '12.4(20)MRA1')
  flag++;
else if (version == '12.4(20)MRB')
  flag++;
else if (version == '12.4(20)MRB1')
  flag++;
else if (version == '12.4(20r)YA')
  flag++;
else if (version == '12.4(20r)YA1')
  flag++;
else if (version == '12.4(20)T')
  flag++;
else if (version == '12.4(20)T1')
  flag++;
else if (version == '12.4(20)T2')
  flag++;
else if (version == '12.4(20)T3')
  flag++;
else if (version == '12.4(20)T4')
  flag++;
else if (version == '12.4(20)T5')
  flag++;
else if (version == '12.4(20)T5a')
  flag++;
else if (version == '12.4(20)T6')
  flag++;
else if (version == '12.4(20)T7')
  flag++;
else if (version == '12.4(20)T8')
  flag++;
else if (version == '12.4(20)T9')
  flag++;
else if (version == '12.4(20)YA')
  flag++;
else if (version == '12.4(20)YA1')
  flag++;
else if (version == '12.4(20)YA2')
  flag++;
else if (version == '12.4(20)YA3')
  flag++;
else if (version == '12.4(21)')
  flag++;
else if (version == '12.4(21a)')
  flag++;
else if (version == '12.4(21a)JX')
  flag++;
else if (version == '12.4(21a)M1')
  flag++;
else if (version == '12.4(22)GC1')
  flag++;
else if (version == '12.4(22)GC1a')
  flag++;
else if (version == '12.4(22)MD')
  flag++;
else if (version == '12.4(22)MD1')
  flag++;
else if (version == '12.4(22)MD2')
  flag++;
else if (version == '12.4(22)MDA')
  flag++;
else if (version == '12.4(22)MDA1')
  flag++;
else if (version == '12.4(22)MDA2')
  flag++;
else if (version == '12.4(22)MDA3')
  flag++;
else if (version == '12.4(22)MDA4')
  flag++;
else if (version == '12.4(22)MDA5')
  flag++;
else if (version == '12.4(22)MDA6')
  flag++;
else if (version == '12.4(22r)T')
  flag++;
else if (version == '12.4(22r)YB')
  flag++;
else if (version == '12.4(22r)YB1')
  flag++;
else if (version == '12.4(22r)YB2')
  flag++;
else if (version == '12.4(22r)YB3')
  flag++;
else if (version == '12.4(22r)YB4')
  flag++;
else if (version == '12.4(22r)YB5')
  flag++;
else if (version == '12.4(22)T')
  flag++;
else if (version == '12.4(22)T1')
  flag++;
else if (version == '12.4(22)T2')
  flag++;
else if (version == '12.4(22)T3')
  flag++;
else if (version == '12.4(22)T4')
  flag++;
else if (version == '12.4(22)T5')
  flag++;
else if (version == '12.4(22)XR')
  flag++;
else if (version == '12.4(22)XR1')
  flag++;
else if (version == '12.4(22)XR10')
  flag++;
else if (version == '12.4(22)XR11')
  flag++;
else if (version == '12.4(22)XR12')
  flag++;
else if (version == '12.4(22)XR2')
  flag++;
else if (version == '12.4(22)XR3')
  flag++;
else if (version == '12.4(22)XR4')
  flag++;
else if (version == '12.4(22)XR5')
  flag++;
else if (version == '12.4(22)XR6')
  flag++;
else if (version == '12.4(22)XR7')
  flag++;
else if (version == '12.4(22)XR8')
  flag++;
else if (version == '12.4(22)XR9')
  flag++;
else if (version == '12.4(22)YB')
  flag++;
else if (version == '12.4(22)YB1')
  flag++;
else if (version == '12.4(22)YB2')
  flag++;
else if (version == '12.4(22)YB3')
  flag++;
else if (version == '12.4(22)YB4')
  flag++;
else if (version == '12.4(22)YB5')
  flag++;
else if (version == '12.4(22)YB6')
  flag++;
else if (version == '12.4(22)YB7')
  flag++;
else if (version == '12.4(22)YB8')
  flag++;
else if (version == '12.4(22)YD')
  flag++;
else if (version == '12.4(22)YD1')
  flag++;
else if (version == '12.4(22)YD2')
  flag++;
else if (version == '12.4(22)YD3')
  flag++;
else if (version == '12.4(22)YD4')
  flag++;
else if (version == '12.4(24)GC1')
  flag++;
else if (version == '12.4(24)GC2')
  flag++;
else if (version == '12.4(24)GC3')
  flag++;
else if (version == '12.4(24)GC3a')
  flag++;
else if (version == '12.4(24)GC4')
  flag++;
else if (version == '12.4(24)MD')
  flag++;
else if (version == '12.4(24)MD1')
  flag++;
else if (version == '12.4(24)MD2')
  flag++;
else if (version == '12.4(24)MD3')
  flag++;
else if (version == '12.4(24)MD4')
  flag++;
else if (version == '12.4(24)MD5')
  flag++;
else if (version == '12.4(24)MD6')
  flag++;
else if (version == '12.4(24)MDA')
  flag++;
else if (version == '12.4(24)MDA1')
  flag++;
else if (version == '12.4(24)MDA10')
  flag++;
else if (version == '12.4(24)MDA2')
  flag++;
else if (version == '12.4(24)MDA3')
  flag++;
else if (version == '12.4(24)MDA4')
  flag++;
else if (version == '12.4(24)MDA5')
  flag++;
else if (version == '12.4(24)MDA6')
  flag++;
else if (version == '12.4(24)MDA7')
  flag++;
else if (version == '12.4(24)MDA8')
  flag++;
else if (version == '12.4(24)MDA9')
  flag++;
else if (version == '12.4(24)MDB')
  flag++;
else if (version == '12.4(24)MDB1')
  flag++;
else if (version == '12.4(24)MDB2')
  flag++;
else if (version == '12.4(24)MDB3')
  flag++;
else if (version == '12.4(24)MDB4')
  flag++;
else if (version == '12.4(24)MDB5')
  flag++;
else if (version == '12.4(24)MDB5a')
  flag++;
else if (version == '12.4(24r)GC2')
  flag++;
else if (version == '12.4(24r)GC3')
  flag++;
else if (version == '12.4(24r)MDA')
  flag++;
else if (version == '12.4(24r)MDB')
  flag++;
else if (version == '12.4(24r)SB')
  flag++;
else if (version == '12.4(24r)T3a')
  flag++;
else if (version == '12.4(24r)YE')
  flag++;
else if (version == '12.4(24r)YF')
  flag++;
else if (version == '12.4(24r)YG')
  flag++;
else if (version == '12.4(24)SB')
  flag++;
else if (version == '12.4(24)T')
  flag++;
else if (version == '12.4(24)T1')
  flag++;
else if (version == '12.4(24)T2')
  flag++;
else if (version == '12.4(24)T3')
  flag++;
else if (version == '12.4(24)T31f')
  flag++;
else if (version == '12.4(24)T34d')
  flag++;
else if (version == '12.4(24)T35c')
  flag++;
else if (version == '12.4(24)T3a')
  flag++;
else if (version == '12.4(24)T3b')
  flag++;
else if (version == '12.4(24)T3c')
  flag++;
else if (version == '12.4(24)T3e')
  flag++;
else if (version == '12.4(24)T3f')
  flag++;
else if (version == '12.4(24)T4')
  flag++;
else if (version == '12.4(24)T4a')
  flag++;
else if (version == '12.4(24)T4b')
  flag++;
else if (version == '12.4(24)T4c')
  flag++;
else if (version == '12.4(24)T5')
  flag++;
else if (version == '12.4(24)T6')
  flag++;
else if (version == '12.4(24)YE')
  flag++;
else if (version == '12.4(24)YE1')
  flag++;
else if (version == '12.4(24)YE2')
  flag++;
else if (version == '12.4(24)YE3')
  flag++;
else if (version == '12.4(24)YE3a')
  flag++;
else if (version == '12.4(24)YE3b')
  flag++;
else if (version == '12.4(24)YE3c')
  flag++;
else if (version == '12.4(24)YE3d')
  flag++;
else if (version == '12.4(24)YE4')
  flag++;
else if (version == '12.4(24)YE5')
  flag++;
else if (version == '12.4(24)YE6')
  flag++;
else if (version == '12.4(24)YE7')
  flag++;
else if (version == '12.4(24)YG')
  flag++;
else if (version == '12.4(24)YG1')
  flag++;
else if (version == '12.4(24)YG2')
  flag++;
else if (version == '12.4(24)YG3')
  flag++;
else if (version == '12.4(24)YG4')
  flag++;
else if (version == '12.4(2)MR')
  flag++;
else if (version == '12.4(2)MR1')
  flag++;
else if (version == '12.4(2r)XM1')
  flag++;
else if (version == '12.4(2)T')
  flag++;
else if (version == '12.4(2)T1')
  flag++;
else if (version == '12.4(2)T2')
  flag++;
else if (version == '12.4(2)T3')
  flag++;
else if (version == '12.4(2)T4')
  flag++;
else if (version == '12.4(2)T5')
  flag++;
else if (version == '12.4(2)T6')
  flag++;
else if (version == '12.4(2)XA')
  flag++;
else if (version == '12.4(2)XA1')
  flag++;
else if (version == '12.4(2)XA2')
  flag++;
else if (version == '12.4(2)XB')
  flag++;
else if (version == '12.4(2)XB052306')
  flag++;
else if (version == '12.4(2)XB1')
  flag++;
else if (version == '12.4(2)XB10')
  flag++;
else if (version == '12.4(2)XB11')
  flag++;
else if (version == '12.4(2)XB12')
  flag++;
else if (version == '12.4(2)XB2')
  flag++;
else if (version == '12.4(2)XB3')
  flag++;
else if (version == '12.4(2)XB4')
  flag++;
else if (version == '12.4(2)XB5')
  flag++;
else if (version == '12.4(2)XB6')
  flag++;
else if (version == '12.4(2)XB7')
  flag++;
else if (version == '12.4(2)XB8')
  flag++;
else if (version == '12.4(2)XB9')
  flag++;
else if (version == '12.4(3)')
  flag++;
else if (version == '12.4(3a)')
  flag++;
else if (version == '12.4(3b)')
  flag++;
else if (version == '12.4(3c)')
  flag++;
else if (version == '12.4(3d)')
  flag++;
else if (version == '12.4(3e)')
  flag++;
else if (version == '12.4(3f)')
  flag++;
else if (version == '12.4(3g)')
  flag++;
else if (version == '12.4(3g)JA')
  flag++;
else if (version == '12.4(3g)JA1')
  flag++;
else if (version == '12.4(3g)JA2')
  flag++;
else if (version == '12.4(3g)JMA')
  flag++;
else if (version == '12.4(3g)JMA1')
  flag++;
else if (version == '12.4(3g)JMB')
  flag++;
else if (version == '12.4(3g)JMC')
  flag++;
else if (version == '12.4(3g)JMC1')
  flag++;
else if (version == '12.4(3g)JMC2')
  flag++;
else if (version == '12.4(3g)JX')
  flag++;
else if (version == '12.4(3g)JX1')
  flag++;
else if (version == '12.4(3g)JX2')
  flag++;
else if (version == '12.4(3h)')
  flag++;
else if (version == '12.4(3h)BAK')
  flag++;
else if (version == '12.4(3i)')
  flag++;
else if (version == '12.4(3j)')
  flag++;
else if (version == '12.4(3)JK')
  flag++;
else if (version == '12.4(3)JK1')
  flag++;
else if (version == '12.4(3)JK2')
  flag++;
else if (version == '12.4(3)JK3')
  flag++;
else if (version == '12.4(3)JL')
  flag++;
else if (version == '12.4(3)JL1')
  flag++;
else if (version == '12.4(4)MR')
  flag++;
else if (version == '12.4(4)MR1')
  flag++;
else if (version == '12.4(4r)XC')
  flag++;
else if (version == '12.4(4r)XD')
  flag++;
else if (version == '12.4(4r)XD1')
  flag++;
else if (version == '12.4(4r)XD2')
  flag++;
else if (version == '12.4(4r)XD3')
  flag++;
else if (version == '12.4(4r)XD4')
  flag++;
else if (version == '12.4(4r)XD5')
  flag++;
else if (version == '12.4(4)T')
  flag++;
else if (version == '12.4(4)T1')
  flag++;
else if (version == '12.4(4)T2')
  flag++;
else if (version == '12.4(4)T3')
  flag++;
else if (version == '12.4(4)T4')
  flag++;
else if (version == '12.4(4)T5')
  flag++;
else if (version == '12.4(4)T6')
  flag++;
else if (version == '12.4(4)T7')
  flag++;
else if (version == '12.4(4)T8')
  flag++;
else if (version == '12.4(4)XC')
  flag++;
else if (version == '12.4(4)XC1')
  flag++;
else if (version == '12.4(4)XC2')
  flag++;
else if (version == '12.4(4)XC3')
  flag++;
else if (version == '12.4(4)XC4')
  flag++;
else if (version == '12.4(4)XC5')
  flag++;
else if (version == '12.4(4)XC6')
  flag++;
else if (version == '12.4(4)XC7')
  flag++;
else if (version == '12.4(4)XD')
  flag++;
else if (version == '12.4(4)XD0')
  flag++;
else if (version == '12.4(4)XD1')
  flag++;
else if (version == '12.4(4)XD10')
  flag++;
else if (version == '12.4(4)XD11')
  flag++;
else if (version == '12.4(4)XD12')
  flag++;
else if (version == '12.4(4)XD2')
  flag++;
else if (version == '12.4(4)XD3')
  flag++;
else if (version == '12.4(4)XD4')
  flag++;
else if (version == '12.4(4)XD5')
  flag++;
else if (version == '12.4(4)XD6')
  flag++;
else if (version == '12.4(4)XD7')
  flag++;
else if (version == '12.4(4)XD7a')
  flag++;
else if (version == '12.4(4)XD7b')
  flag++;
else if (version == '12.4(4)XD7c')
  flag++;
else if (version == '12.4(4)XD8')
  flag++;
else if (version == '12.4(4)XD8a')
  flag++;
else if (version == '12.4(4)XD9')
  flag++;
else if (version == '12.4(5)')
  flag++;
else if (version == '12.4(555)TEST')
  flag++;
else if (version == '12.4(567b)TST')
  flag++;
else if (version == '12.4(57)ARF')
  flag++;
else if (version == '12.4(57)ARF2')
  flag++;
else if (version == '12.4(57)COMP')
  flag++;
else if (version == '12.4(5a)')
  flag++;
else if (version == '12.4(5a)M0')
  flag++;
else if (version == '12.4(5b)')
  flag++;
else if (version == '12.4(5c)')
  flag++;
else if (version == '12.4(6)MR')
  flag++;
else if (version == '12.4(6)MR1')
  flag++;
else if (version == '12.4(6r)XE')
  flag++;
else if (version == '12.4(6)T')
  flag++;
else if (version == '12.4(6)T1')
  flag++;
else if (version == '12.4(6)T10')
  flag++;
else if (version == '12.4(6)T11')
  flag++;
else if (version == '12.4(6)T12')
  flag++;
else if (version == '12.4(6)T2')
  flag++;
else if (version == '12.4(6)T3')
  flag++;
else if (version == '12.4(6)T4')
  flag++;
else if (version == '12.4(6)T5')
  flag++;
else if (version == '12.4(6)T5a')
  flag++;
else if (version == '12.4(6)T5b')
  flag++;
else if (version == '12.4(6)T5c')
  flag++;
else if (version == '12.4(6)T5d')
  flag++;
else if (version == '12.4(6)T5e')
  flag++;
else if (version == '12.4(6)T5f')
  flag++;
else if (version == '12.4(6)T6')
  flag++;
else if (version == '12.4(6)T7')
  flag++;
else if (version == '12.4(6)T8')
  flag++;
else if (version == '12.4(6)T9')
  flag++;
else if (version == '12.4(6t)EB2')
  flag++;
else if (version == '12.4(6t)EB3')
  flag++;
else if (version == '12.4(6t)EB4')
  flag++;
else if (version == '12.4(6t)EB5')
  flag++;
else if (version == '12.4(6)XE')
  flag++;
else if (version == '12.4(6)XE1')
  flag++;
else if (version == '12.4(6)XE2')
  flag++;
else if (version == '12.4(6)XE3')
  flag++;
else if (version == '12.4(6)XE4')
  flag++;
else if (version == '12.4(6)XP')
  flag++;
else if (version == '12.4(6)XT')
  flag++;
else if (version == '12.4(6)XT1')
  flag++;
else if (version == '12.4(6)XT2')
  flag++;
else if (version == '12.4(7)')
  flag++;
else if (version == '12.4(77)T')
  flag++;
else if (version == '12.4(789a)TST')
  flag++;
else if (version == '12.4(7a)')
  flag++;
else if (version == '12.4(7b)')
  flag++;
else if (version == '12.4(7c)')
  flag++;
else if (version == '12.4(7d)')
  flag++;
else if (version == '12.4(7e)')
  flag++;
else if (version == '12.4(7f)')
  flag++;
else if (version == '12.4(7g)')
  flag++;
else if (version == '12.4(7h)')
  flag++;
else if (version == '12.4(8)')
  flag++;
else if (version == '12.4(80)TEST')
  flag++;
else if (version == '12.4(8a)')
  flag++;
else if (version == '12.4(8b)')
  flag++;
else if (version == '12.4(8c)')
  flag++;
else if (version == '12.4(8d)')
  flag++;
else if (version == '12.4(95r)TST')
  flag++;
else if (version == '12.4(99)')
  flag++;
else if (version == '12.4(999)JA')
  flag++;
else if (version == '12.4(999)XQ')
  flag++;
else if (version == '12.4(99)TEST4')
  flag++;
else if (version == '12.4(99)TST')
  flag++;
else if (version == '12.4(9)MR')
  flag++;
else if (version == '12.4(9)T')
  flag++;
else if (version == '12.4(9)T0a')
  flag++;
else if (version == '12.4(9)T1')
  flag++;
else if (version == '12.4(9)T2')
  flag++;
else if (version == '12.4(9)T3')
  flag++;
else if (version == '12.4(9)T4')
  flag++;
else if (version == '12.4(9)T5')
  flag++;
else if (version == '12.4(9)T6')
  flag++;
else if (version == '12.4(9)T7')
  flag++;
else if (version == '12.4(9)XG')
  flag++;
else if (version == '12.4(9)XG1')
  flag++;
else if (version == '12.4(9)XG2')
  flag++;
else if (version == '12.4(9)XG3')
  flag++;
else if (version == '12.4(9)XG4')
  flag++;
else if (version == '12.4(9)XG5')
  flag++;
else if (version == '12.5(1)')
  flag++;
else if (version == '12.5(88888883)')
  flag++;
else if (version == '12.5(888888882)')
  flag++;
else if (version == '12.5(98)TST')
  flag++;
else if (version == '12.9(9)S0225')
  flag++;
else if (version == '15.0(1)')
  flag++;
else if (version == '15.0(10)SG')
  flag++;
else if (version == '15.0(1)EW')
  flag++;
else if (version == '15.0(1)M1')
  flag++;
else if (version == '15.0(1)M2')
  flag++;
else if (version == '15.0(1)M3')
  flag++;
else if (version == '15.0(1)M4')
  flag++;
else if (version == '15.0(1)M5')
  flag++;
else if (version == '15.0(1)M6')
  flag++;
else if (version == '15.0(1)M6a')
  flag++;
else if (version == '15.0(1)M7')
  flag++;
else if (version == '15.0(1r)')
  flag++;
else if (version == '15.0(1r)M1')
  flag++;
else if (version == '15.0(1r)M10')
  flag++;
else if (version == '15.0(1r)M11')
  flag++;
else if (version == '15.0(1r)M12')
  flag++;
else if (version == '15.0(1r)M13')
  flag++;
else if (version == '15.0(1r)M14')
  flag++;
else if (version == '15.0(1r)M15')
  flag++;
else if (version == '15.0(1r)M2')
  flag++;
else if (version == '15.0(1r)M3')
  flag++;
else if (version == '15.0(1r)M4')
  flag++;
else if (version == '15.0(1r)M5')
  flag++;
else if (version == '15.0(1r)M6')
  flag++;
else if (version == '15.0(1r)M7')
  flag++;
else if (version == '15.0(1r)M8')
  flag++;
else if (version == '15.0(1r)M9')
  flag++;
else if (version == '15.0(1r)S')
  flag++;
else if (version == '15.0(1r)XA')
  flag++;
else if (version == '15.0(1r)XA3')
  flag++;
else if (version == '15.0(1)SE')
  flag++;
else if (version == '15.0(1)SE1')
  flag++;
else if (version == '15.0(1)SE2')
  flag++;
else if (version == '15.0(1)XA')
  flag++;
else if (version == '15.0(1)XA1')
  flag++;
else if (version == '15.0(1)XA2')
  flag++;
else if (version == '15.0(1)XA3')
  flag++;
else if (version == '15.0(1)XA4')
  flag++;
else if (version == '15.0(1)XA5')
  flag++;
else if (version == '15.0(1)XO')
  flag++;
else if (version == '15.0(1)XO1')
  flag++;
else if (version == '15.0(2)EW')
  flag++;
else if (version == '15.0(2)SG')
  flag++;
else if (version == '15.0(2)SG1')
  flag++;
else if (version == '15.0(2)SG2')
  flag++;
else if (version == '15.0(2)SG3')
  flag++;
else if (version == '15.0(2)XO')
  flag++;
else if (version == '15.0(3)EW')
  flag++;
else if (version == '15.0(3)SG')
  flag++;
else if (version == '15.0(4)EW')
  flag++;
else if (version == '15.0(4)SG')
  flag++;
else if (version == '15.0(5)EW')
  flag++;
else if (version == '15.0(5)SG')
  flag++;
else if (version == '15.0(6)EW')
  flag++;
else if (version == '15.0(6)SG')
  flag++;
else if (version == '15.0(7)EW')
  flag++;
else if (version == '15.0(7)SG')
  flag++;
else if (version == '15.0(8)EW')
  flag++;
else if (version == '15.0(8)SG')
  flag++;
else if (version == '15.0(98)CCAI')
  flag++;
else if (version == '15.0(9988)M1')
  flag++;
else if (version == '15.0(9999)M1')
  flag++;
else if (version == '15.0(9)SG')
  flag++;
else if (version == '15.1(1r)T1')
  flag++;
else if (version == '15.1(1r)T2')
  flag++;
else if (version == '15.1(1r)T3')
  flag++;
else if (version == '15.1(1r)T4')
  flag++;
else if (version == '15.1(1)T')
  flag++;
else if (version == '15.1(1)T1')
  flag++;
else if (version == '15.1(1)T2')
  flag++;
else if (version == '15.1(1)T3')
  flag++;
else if (version == '15.1(1)T4')
  flag++;
else if (version == '15.1(1)XB')
  flag++;
else if (version == '15.1(1)XB1')
  flag++;
else if (version == '15.1(1)XB2')
  flag++;
else if (version == '15.1(1)XB3')
  flag++;
else if (version == '15.1(2)GC')
  flag++;
else if (version == '15.1(2)GC1')
  flag++;
else if (version == '15.1(2r)GC')
  flag++;
else if (version == '15.1(2r)GC1')
  flag++;
else if (version == '15.1(2r)T')
  flag++;
else if (version == '15.1(2r)T1')
  flag++;
else if (version == '15.1(2r)T2')
  flag++;
else if (version == '15.1(2r)T3')
  flag++;
else if (version == '15.1(2)T')
  flag++;
else if (version == '15.1(2)T0a')
  flag++;
else if (version == '15.1(2)T1')
  flag++;
else if (version == '15.1(2)T2')
  flag++;
else if (version == '15.1(2)T2a')
  flag++;
else if (version == '15.1(2)T3')
  flag++;
else if (version == '15.1(2)T4')
  flag++;
else if (version == '15.1(4)')
  flag++;
else if (version == '15.1(4)M0a')
  flag++;
else if (version == '15.1(4)M0b')
  flag++;
else if (version == '15.1(4)M1')
  flag++;
else if (version == '15.1(4)M2')
  flag++;
else if (version == '15.1(4)M3')
  flag++;
else if (version == '15.1(4)M3a')
  flag++;
else if (version == '15.1(4r)M2')
  flag++;
else if (version == '15.1(4)XB4')
  flag++;
else if (version == '15.1(4)XB5')
  flag++;
else if (version == '15.1(4)XB5a')
  flag++;
else if (version == '15.1(4)XB6')
  flag++;
else if (version == '15.1(4)XB7')
  flag++;
else if (version == '15.1(9999)CCAI')
  flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_http_server_status", "show ip http server status");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"HTTP server status:\s+Enabled", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"HTTP secure server status:\s+Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_http_server_session-module", "show ip http server session-module");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"WEB_EXEC[^\r\n]+Active", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
