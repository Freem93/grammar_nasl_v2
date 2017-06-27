#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17790);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");

 script_cve_id("CVE-2007-4430");
 script_osvdb_id(37104);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsk14633");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsk33054");
 script_xref(name:"CISCO-SR", value:"cisco-sr-20070912-regexp");

 script_name(english:"Cisco Regular Expression Processing DoS");
 script_summary(english:"Checks the version of Cisco IOS.");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"On September 19, 2007, Cisco released a security response for a
denial of service vulnerability in the regular expression processing
in IOS. Exploitation of this vulnerability could result in a denial
of service crash and reload. This plugin checks if the appropriate
fix for the advisory has been installed.");

 # http://www.cisco.com/en/US/products/products_security_response09186a00808bb91c.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75155889");
 script_set_attribute(attribute:"see_also", value:"https://puck.nether.net/pipermail/cisco-nsp/2007-August/043010.html");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory
cisco-sr-20070912-regexp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/17");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/12/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2012-2014 Tenable Network Security, Inc.");

 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");

 exit(0);
}

include("cisco_func.inc");
include("audit.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.2(100)EWA')
  security_warning(0);
else if (version == '12.2(100)EWA')
  security_warning(0);
else if (version == '12.2(101)EWA')
  security_warning(0);
else if (version == '12.2(101)EWA')
  security_warning(0);
else if (version == '12.2(102)EWA')
  security_warning(0);
else if (version == '12.2(102)EWA')
  security_warning(0);
else if (version == '12.2(10)SBT112')
  security_warning(0);
else if (version == '12.2(11r)SZ')
  security_warning(0);
else if (version == '12.2(11r)YZ')
  security_warning(0);
else if (version == '12.2(11r)YZ1')
  security_warning(0);
else if (version == '12.2(11r)YZ2')
  security_warning(0);
else if (version == '12.2(11r)YZ3')
  security_warning(0);
else if (version == '12.2(11)SBT112')
  security_warning(0);
else if (version == '12.2(11)YX')
  security_warning(0);
else if (version == '12.2(11)YX1')
  security_warning(0);
else if (version == '12.2(11)YZ')
  security_warning(0);
else if (version == '12.2(11)YZ1')
  security_warning(0);
else if (version == '12.2(11)YZ2')
  security_warning(0);
else if (version == '12.2(11)YZ3')
  security_warning(0);
else if (version == '12.2(12g)TEST')
  security_warning(0);
else if (version == '12.2(12h)SAVE')
  security_warning(0);
else if (version == '12.2(12)SBT112')
  security_warning(0);
else if (version == '12.2(14r)SZ')
  security_warning(0);
else if (version == '12.2(14r)SZ1')
  security_warning(0);
else if (version == '12.2(14)SU')
  security_warning(0);
else if (version == '12.2(14)SU1')
  security_warning(0);
else if (version == '12.2(14)SU2')
  security_warning(0);
else if (version == '12.2(14)SX')
  security_warning(0);
else if (version == '12.2(14)SX05282003')
  security_warning(0);
else if (version == '12.2(14)SX1')
  security_warning(0);
else if (version == '12.2(14)SX1a')
  security_warning(0);
else if (version == '12.2(14)SX2')
  security_warning(0);
else if (version == '12.2(14)SY')
  security_warning(0);
else if (version == '12.2(14)SY1')
  security_warning(0);
else if (version == '12.2(14)SY2')
  security_warning(0);
else if (version == '12.2(14)SY3')
  security_warning(0);
else if (version == '12.2(14)SY4')
  security_warning(0);
else if (version == '12.2(14)SY5')
  security_warning(0);
else if (version == '12.2(14)SZ')
  security_warning(0);
else if (version == '12.2(14)SZ1')
  security_warning(0);
else if (version == '12.2(14)SZ2')
  security_warning(0);
else if (version == '12.2(14)SZ3')
  security_warning(0);
else if (version == '12.2(14)SZ4')
  security_warning(0);
else if (version == '12.2(14)SZ5')
  security_warning(0);
else if (version == '12.2(14)SZ6')
  security_warning(0);
else if (version == '12.2(14)ZA')
  security_warning(0);
else if (version == '12.2(14)ZA1')
  security_warning(0);
else if (version == '12.2(14)ZA2')
  security_warning(0);
else if (version == '12.2(14)ZA3')
  security_warning(0);
else if (version == '12.2(14)ZA4')
  security_warning(0);
else if (version == '12.2(14)ZA5')
  security_warning(0);
else if (version == '12.2(14)ZA6')
  security_warning(0);
else if (version == '12.2(14)ZA7')
  security_warning(0);
else if (version == '12.2(16b)REG1')
  security_warning(0);
else if (version == '12.2(17a)SX')
  security_warning(0);
else if (version == '12.2(17a)SX1')
  security_warning(0);
else if (version == '12.2(17a)SX2')
  security_warning(0);
else if (version == '12.2(17a)SX3')
  security_warning(0);
else if (version == '12.2(17a)SX4')
  security_warning(0);
else if (version == '12.2(17b)SXA')
  security_warning(0);
else if (version == '12.2(17b)SXA')
  security_warning(0);
else if (version == '12.2(17b)SXA1')
  security_warning(0);
else if (version == '12.2(17b)SXA1')
  security_warning(0);
else if (version == '12.2(17b)SXA2')
  security_warning(0);
else if (version == '12.2(17b)SXA2')
  security_warning(0);
else if (version == '12.2(17d)SXB')
  security_warning(0);
else if (version == '12.2(17d)SXB')
  security_warning(0);
else if (version == '12.2(17d)SXB1')
  security_warning(0);
else if (version == '12.2(17d)SXB1')
  security_warning(0);
else if (version == '12.2(17d)SXB10')
  security_warning(0);
else if (version == '12.2(17d)SXB10')
  security_warning(0);
else if (version == '12.2(17d)SXB11')
  security_warning(0);
else if (version == '12.2(17d)SXB11')
  security_warning(0);
else if (version == '12.2(17d)SXB11a')
  security_warning(0);
else if (version == '12.2(17d)SXB11a')
  security_warning(0);
else if (version == '12.2(17d)SXB2')
  security_warning(0);
else if (version == '12.2(17d)SXB2')
  security_warning(0);
else if (version == '12.2(17d)SXB3')
  security_warning(0);
else if (version == '12.2(17d)SXB3')
  security_warning(0);
else if (version == '12.2(17d)SXB4')
  security_warning(0);
else if (version == '12.2(17d)SXB4')
  security_warning(0);
else if (version == '12.2(17d)SXB5')
  security_warning(0);
else if (version == '12.2(17d)SXB5')
  security_warning(0);
else if (version == '12.2(17d)SXB6')
  security_warning(0);
else if (version == '12.2(17d)SXB6')
  security_warning(0);
else if (version == '12.2(17d)SXB7')
  security_warning(0);
else if (version == '12.2(17d)SXB7')
  security_warning(0);
else if (version == '12.2(17d)SXB8')
  security_warning(0);
else if (version == '12.2(17d)SXB8')
  security_warning(0);
else if (version == '12.2(17d)SXB9')
  security_warning(0);
else if (version == '12.2(17d)SXB9')
  security_warning(0);
else if (version == '12.2(17r)SX')
  security_warning(0);
else if (version == '12.2(17r)SX1')
  security_warning(0);
else if (version == '12.2(17r)SX2')
  security_warning(0);
else if (version == '12.2(17r)SX3')
  security_warning(0);
else if (version == '12.2(17r)SX5')
  security_warning(0);
else if (version == '12.2(17r)SX6')
  security_warning(0);
else if (version == '12.2(17r)SX7')
  security_warning(0);
else if (version == '12.2(17r)SXB3')
  security_warning(0);
else if (version == '12.2(17r)SXB3')
  security_warning(0);
else if (version == '12.2(18)IXA')
  security_warning(0);
else if (version == '12.2(18)IXA')
  security_warning(0);
else if (version == '12.2(18)IXB')
  security_warning(0);
else if (version == '12.2(18)IXB')
  security_warning(0);
else if (version == '12.2(18)IXB1')
  security_warning(0);
else if (version == '12.2(18)IXB1')
  security_warning(0);
else if (version == '12.2(18)IXB2')
  security_warning(0);
else if (version == '12.2(18)IXB2')
  security_warning(0);
else if (version == '12.2(18)IXC')
  security_warning(0);
else if (version == '12.2(18)IXC')
  security_warning(0);
else if (version == '12.2(18)IXD')
  security_warning(0);
else if (version == '12.2(18)IXD')
  security_warning(0);
else if (version == '12.2(18)IXD1')
  security_warning(0);
else if (version == '12.2(18)IXD1')
  security_warning(0);
else if (version == '12.2(18)IXE')
  security_warning(0);
else if (version == '12.2(18)IXE')
  security_warning(0);
else if (version == '12.2(18)IXF')
  security_warning(0);
else if (version == '12.2(18)IXF')
  security_warning(0);
else if (version == '12.2(18)IXF1')
  security_warning(0);
else if (version == '12.2(18)IXF1')
  security_warning(0);
else if (version == '12.2(18)IXG')
  security_warning(0);
else if (version == '12.2(18)IXG')
  security_warning(0);
else if (version == '12.2(18)IXH')
  security_warning(0);
else if (version == '12.2(18)IXH')
  security_warning(0);
else if (version == '12.2(18)IXH1')
  security_warning(0);
else if (version == '12.2(18)IXH1')
  security_warning(0);
else if (version == '12.2(18r)SX1')
  security_warning(0);
else if (version == '12.2(18r)SX2')
  security_warning(0);
else if (version == '12.2(18r)SX3')
  security_warning(0);
else if (version == '12.2(18r)SX4')
  security_warning(0);
else if (version == '12.2(18r)SX5')
  security_warning(0);
else if (version == '12.2(18r)SX7')
  security_warning(0);
else if (version == '12.2(18r)SX8')
  security_warning(0);
else if (version == '12.2(18r)SX9')
  security_warning(0);
else if (version == '12.2(18)SE')
  security_warning(0);
else if (version == '12.2(18)SE1')
  security_warning(0);
else if (version == '12.2(18)SO')
  security_warning(0);
else if (version == '12.2(18)SO1')
  security_warning(0);
else if (version == '12.2(18)SO2')
  security_warning(0);
else if (version == '12.2(18)SO3')
  security_warning(0);
else if (version == '12.2(18)SO4')
  security_warning(0);
else if (version == '12.2(18)SO5')
  security_warning(0);
else if (version == '12.2(18)SO6')
  security_warning(0);
else if (version == '12.2(18)SO7')
  security_warning(0);
else if (version == '12.2(18)SV')
  security_warning(0);
else if (version == '12.2(18)SV1')
  security_warning(0);
else if (version == '12.2(18)SV2')
  security_warning(0);
else if (version == '12.2(18)SV3')
  security_warning(0);
else if (version == '12.2(18)SW')
  security_warning(0);
else if (version == '12.2(18)SXD')
  security_warning(0);
else if (version == '12.2(18)SXD')
  security_warning(0);
else if (version == '12.2(18)SXD1')
  security_warning(0);
else if (version == '12.2(18)SXD1')
  security_warning(0);
else if (version == '12.2(18)SXD2')
  security_warning(0);
else if (version == '12.2(18)SXD2')
  security_warning(0);
else if (version == '12.2(18)SXD3')
  security_warning(0);
else if (version == '12.2(18)SXD3')
  security_warning(0);
else if (version == '12.2(18)SXD4')
  security_warning(0);
else if (version == '12.2(18)SXD4')
  security_warning(0);
else if (version == '12.2(18)SXD5')
  security_warning(0);
else if (version == '12.2(18)SXD5')
  security_warning(0);
else if (version == '12.2(18)SXD6')
  security_warning(0);
else if (version == '12.2(18)SXD6')
  security_warning(0);
else if (version == '12.2(18)SXD7')
  security_warning(0);
else if (version == '12.2(18)SXD7')
  security_warning(0);
else if (version == '12.2(18)SXD7a')
  security_warning(0);
else if (version == '12.2(18)SXD7a')
  security_warning(0);
else if (version == '12.2(18)SXD7b')
  security_warning(0);
else if (version == '12.2(18)SXD7b')
  security_warning(0);
else if (version == '12.2(18)SXE')
  security_warning(0);
else if (version == '12.2(18)SXE')
  security_warning(0);
else if (version == '12.2(18)SXE1')
  security_warning(0);
else if (version == '12.2(18)SXE1')
  security_warning(0);
else if (version == '12.2(18)SXE2')
  security_warning(0);
else if (version == '12.2(18)SXE2')
  security_warning(0);
else if (version == '12.2(18)SXE3')
  security_warning(0);
else if (version == '12.2(18)SXE3')
  security_warning(0);
else if (version == '12.2(18)SXE4')
  security_warning(0);
else if (version == '12.2(18)SXE4')
  security_warning(0);
else if (version == '12.2(18)SXE5')
  security_warning(0);
else if (version == '12.2(18)SXE5')
  security_warning(0);
else if (version == '12.2(18)SXE6')
  security_warning(0);
else if (version == '12.2(18)SXE6')
  security_warning(0);
else if (version == '12.2(18)SXE6a')
  security_warning(0);
else if (version == '12.2(18)SXE6a')
  security_warning(0);
else if (version == '12.2(18)SXE6b')
  security_warning(0);
else if (version == '12.2(18)SXE6b')
  security_warning(0);
else if (version == '12.2(18)SXF')
  security_warning(0);
else if (version == '12.2(18)SXF')
  security_warning(0);
else if (version == '12.2(18)SXF1')
  security_warning(0);
else if (version == '12.2(18)SXF1')
  security_warning(0);
else if (version == '12.2(18)SXF10')
  security_warning(0);
else if (version == '12.2(18)SXF10')
  security_warning(0);
else if (version == '12.2(18)SXF10a')
  security_warning(0);
else if (version == '12.2(18)SXF10a')
  security_warning(0);
else if (version == '12.2(18)SXF11')
  security_warning(0);
else if (version == '12.2(18)SXF11')
  security_warning(0);
else if (version == '12.2(18)SXF12')
  security_warning(0);
else if (version == '12.2(18)SXF12')
  security_warning(0);
else if (version == '12.2(18)SXF12a')
  security_warning(0);
else if (version == '12.2(18)SXF12a')
  security_warning(0);
else if (version == '12.2(18)SXF13')
  security_warning(0);
else if (version == '12.2(18)SXF13a')
  security_warning(0);
else if (version == '12.2(18)SXF13b')
  security_warning(0);
else if (version == '12.2(18)SXF14')
  security_warning(0);
else if (version == '12.2(18)SXF15')
  security_warning(0);
else if (version == '12.2(18)SXF15a')
  security_warning(0);
else if (version == '12.2(18)SXF16')
  security_warning(0);
else if (version == '12.2(18)SXF17')
  security_warning(0);
else if (version == '12.2(18)SXF17a')
  security_warning(0);
else if (version == '12.2(18)SXF17b')
  security_warning(0);
else if (version == '12.2(18)SXF2')
  security_warning(0);
else if (version == '12.2(18)SXF2')
  security_warning(0);
else if (version == '12.2(18)SXF3')
  security_warning(0);
else if (version == '12.2(18)SXF3')
  security_warning(0);
else if (version == '12.2(18)SXF4')
  security_warning(0);
else if (version == '12.2(18)SXF4')
  security_warning(0);
else if (version == '12.2(18)SXF5')
  security_warning(0);
else if (version == '12.2(18)SXF5')
  security_warning(0);
else if (version == '12.2(18)SXF6')
  security_warning(0);
else if (version == '12.2(18)SXF6')
  security_warning(0);
else if (version == '12.2(18)SXF7')
  security_warning(0);
else if (version == '12.2(18)SXF7')
  security_warning(0);
else if (version == '12.2(18)SXF8')
  security_warning(0);
else if (version == '12.2(18)SXF8')
  security_warning(0);
else if (version == '12.2(18)SXF9')
  security_warning(0);
else if (version == '12.2(18)SXF9')
  security_warning(0);
else if (version == '12.2(18)ZU')
  security_warning(0);
else if (version == '12.2(18)ZU1')
  security_warning(0);
else if (version == '12.2(18)ZU2')
  security_warning(0);
else if (version == '12.2(18)ZY')
  security_warning(0);
else if (version == '12.2(18)ZY1')
  security_warning(0);
else if (version == '12.2(18)ZY2')
  security_warning(0);
else if (version == '12.2(18)ZY2')
  security_warning(0);
else if (version == '12.2(18)ZYA')
  security_warning(0);
else if (version == '12.2(18)ZYA1')
  security_warning(0);
else if (version == '12.2(18)ZYA2')
  security_warning(0);
else if (version == '12.2(18)ZYA3')
  security_warning(0);
else if (version == '12.2(18)ZYA3a')
  security_warning(0);
else if (version == '12.2(18)ZYA3b')
  security_warning(0);
else if (version == '12.2(18)ZYA3c')
  security_warning(0);
else if (version == '12.2(19)SAVE')
  security_warning(0);
else if (version == '12.2(19)SW')
  security_warning(0);
else if (version == '12.2(1)SBT112')
  security_warning(0);
else if (version == '12.2(20)EWA')
  security_warning(0);
else if (version == '12.2(20)EWA')
  security_warning(0);
else if (version == '12.2(20)EWA1')
  security_warning(0);
else if (version == '12.2(20)EWA1')
  security_warning(0);
else if (version == '12.2(20)EWA2')
  security_warning(0);
else if (version == '12.2(20)EWA2')
  security_warning(0);
else if (version == '12.2(20)EWA3')
  security_warning(0);
else if (version == '12.2(20)EWA3')
  security_warning(0);
else if (version == '12.2(20)EWA4')
  security_warning(0);
else if (version == '12.2(20)EWA4')
  security_warning(0);
else if (version == '12.2(20)SE')
  security_warning(0);
else if (version == '12.2(20)SE1')
  security_warning(0);
else if (version == '12.2(20)SE2')
  security_warning(0);
else if (version == '12.2(20)SE3')
  security_warning(0);
else if (version == '12.2(20)SE4')
  security_warning(0);
else if (version == '12.2(20)SW')
  security_warning(0);
else if (version == '12.2(21)BASE')
  security_warning(0);
else if (version == '12.2(21)SW')
  security_warning(0);
else if (version == '12.2(21)SW01a')
  security_warning(0);
else if (version == '12.2(21)SW1')
  security_warning(0);
else if (version == '12.2(22)SV')
  security_warning(0);
else if (version == '12.2(22)SV1')
  security_warning(0);
else if (version == '12.2(23)SV')
  security_warning(0);
else if (version == '12.2(23)SV1')
  security_warning(0);
else if (version == '12.2(23)SW')
  security_warning(0);
else if (version == '12.2(23)SW1')
  security_warning(0);
else if (version == '12.2(24)SV')
  security_warning(0);
else if (version == '12.2(24)SV1')
  security_warning(0);
else if (version == '12.2(25)EWA')
  security_warning(0);
else if (version == '12.2(25)EWA')
  security_warning(0);
else if (version == '12.2(25)EWA1')
  security_warning(0);
else if (version == '12.2(25)EWA1')
  security_warning(0);
else if (version == '12.2(25)EWA10')
  security_warning(0);
else if (version == '12.2(25)EWA10')
  security_warning(0);
else if (version == '12.2(25)EWA11')
  security_warning(0);
else if (version == '12.2(25)EWA11')
  security_warning(0);
else if (version == '12.2(25)EWA12')
  security_warning(0);
else if (version == '12.2(25)EWA12')
  security_warning(0);
else if (version == '12.2(25)EWA13')
  security_warning(0);
else if (version == '12.2(25)EWA13')
  security_warning(0);
else if (version == '12.2(25)EWA14')
  security_warning(0);
else if (version == '12.2(25)EWA14')
  security_warning(0);
else if (version == '12.2(25)EWA2')
  security_warning(0);
else if (version == '12.2(25)EWA2')
  security_warning(0);
else if (version == '12.2(25)EWA3')
  security_warning(0);
else if (version == '12.2(25)EWA3')
  security_warning(0);
else if (version == '12.2(25)EWA4')
  security_warning(0);
else if (version == '12.2(25)EWA4')
  security_warning(0);
else if (version == '12.2(25)EWA5')
  security_warning(0);
else if (version == '12.2(25)EWA5')
  security_warning(0);
else if (version == '12.2(25)EWA6')
  security_warning(0);
else if (version == '12.2(25)EWA6')
  security_warning(0);
else if (version == '12.2(25)EWA7')
  security_warning(0);
else if (version == '12.2(25)EWA7')
  security_warning(0);
else if (version == '12.2(25)EWA8')
  security_warning(0);
else if (version == '12.2(25)EWA8')
  security_warning(0);
else if (version == '12.2(25)EWA9')
  security_warning(0);
else if (version == '12.2(25)EWA9')
  security_warning(0);
else if (version == '12.2(25)SE')
  security_warning(0);
else if (version == '12.2(25)SE2')
  security_warning(0);
else if (version == '12.2(25)SE3')
  security_warning(0);
else if (version == '12.2(25)SEA')
  security_warning(0);
else if (version == '12.2(25)SEA')
  security_warning(0);
else if (version == '12.2(25)SEB')
  security_warning(0);
else if (version == '12.2(25)SEB')
  security_warning(0);
else if (version == '12.2(25)SEB1')
  security_warning(0);
else if (version == '12.2(25)SEB1')
  security_warning(0);
else if (version == '12.2(25)SEB2')
  security_warning(0);
else if (version == '12.2(25)SEB2')
  security_warning(0);
else if (version == '12.2(25)SEB3')
  security_warning(0);
else if (version == '12.2(25)SEB3')
  security_warning(0);
else if (version == '12.2(25)SEB4')
  security_warning(0);
else if (version == '12.2(25)SEB4')
  security_warning(0);
else if (version == '12.2(25)SEC')
  security_warning(0);
else if (version == '12.2(25)SEC')
  security_warning(0);
else if (version == '12.2(25)SEC1')
  security_warning(0);
else if (version == '12.2(25)SEC1')
  security_warning(0);
else if (version == '12.2(25)SEC2')
  security_warning(0);
else if (version == '12.2(25)SEC2')
  security_warning(0);
else if (version == '12.2(25)SED')
  security_warning(0);
else if (version == '12.2(25)SED')
  security_warning(0);
else if (version == '12.2(25)SED1')
  security_warning(0);
else if (version == '12.2(25)SED1')
  security_warning(0);
else if (version == '12.2(25)SEE')
  security_warning(0);
else if (version == '12.2(25)SEE')
  security_warning(0);
else if (version == '12.2(25)SEE1')
  security_warning(0);
else if (version == '12.2(25)SEE1')
  security_warning(0);
else if (version == '12.2(25)SEE2')
  security_warning(0);
else if (version == '12.2(25)SEE2')
  security_warning(0);
else if (version == '12.2(25)SEE3')
  security_warning(0);
else if (version == '12.2(25)SEE3')
  security_warning(0);
else if (version == '12.2(25)SEE4')
  security_warning(0);
else if (version == '12.2(25)SEE4')
  security_warning(0);
else if (version == '12.2(25)SEF')
  security_warning(0);
else if (version == '12.2(25)SEF')
  security_warning(0);
else if (version == '12.2(25)SEF1')
  security_warning(0);
else if (version == '12.2(25)SEF1')
  security_warning(0);
else if (version == '12.2(25)SEF2')
  security_warning(0);
else if (version == '12.2(25)SEF2')
  security_warning(0);
else if (version == '12.2(25)SEF3')
  security_warning(0);
else if (version == '12.2(25)SEF3')
  security_warning(0);
else if (version == '12.2(25)SEG')
  security_warning(0);
else if (version == '12.2(25)SEG')
  security_warning(0);
else if (version == '12.2(25)SEG1')
  security_warning(0);
else if (version == '12.2(25)SEG1')
  security_warning(0);
else if (version == '12.2(25)SEG2')
  security_warning(0);
else if (version == '12.2(25)SEG2')
  security_warning(0);
else if (version == '12.2(25)SEG3')
  security_warning(0);
else if (version == '12.2(25)SEG3')
  security_warning(0);
else if (version == '12.2(25)SEG4')
  security_warning(0);
else if (version == '12.2(25)SEG4')
  security_warning(0);
else if (version == '12.2(25)SEG5')
  security_warning(0);
else if (version == '12.2(25)SEG5')
  security_warning(0);
else if (version == '12.2(25)SEG6')
  security_warning(0);
else if (version == '12.2(25)SEG6')
  security_warning(0);
else if (version == '12.2(25)SG')
  security_warning(0);
else if (version == '12.2(25)SG1')
  security_warning(0);
else if (version == '12.2(25)SG2')
  security_warning(0);
else if (version == '12.2(25)SG3')
  security_warning(0);
else if (version == '12.2(25)SG4')
  security_warning(0);
else if (version == '12.2(25)SV')
  security_warning(0);
else if (version == '12.2(25)SV2')
  security_warning(0);
else if (version == '12.2(25)SV3')
  security_warning(0);
else if (version == '12.2(25)SW')
  security_warning(0);
else if (version == '12.2(25)SW1')
  security_warning(0);
else if (version == '12.2(25)SW10')
  security_warning(0);
else if (version == '12.2(25)SW11')
  security_warning(0);
else if (version == '12.2(25)SW12')
  security_warning(0);
else if (version == '12.2(25)SW2')
  security_warning(0);
else if (version == '12.2(25)SW3')
  security_warning(0);
else if (version == '12.2(25)SW3a')
  security_warning(0);
else if (version == '12.2(25)SW3b')
  security_warning(0);
else if (version == '12.2(25)SW4')
  security_warning(0);
else if (version == '12.2(25)SW4a')
  security_warning(0);
else if (version == '12.2(25)SW5')
  security_warning(0);
else if (version == '12.2(25)SW6')
  security_warning(0);
else if (version == '12.2(25)SW7')
  security_warning(0);
else if (version == '12.2(25)SW8')
  security_warning(0);
else if (version == '12.2(25)SW9')
  security_warning(0);
else if (version == '12.2(26)SV')
  security_warning(0);
else if (version == '12.2(26)SV1')
  security_warning(0);
else if (version == '12.2(27)SBA')
  security_warning(0);
else if (version == '12.2(27)SBA')
  security_warning(0);
else if (version == '12.2(27)SBA1')
  security_warning(0);
else if (version == '12.2(27)SBA1')
  security_warning(0);
else if (version == '12.2(27)SBA2')
  security_warning(0);
else if (version == '12.2(27)SBA2')
  security_warning(0);
else if (version == '12.2(27)SBA3')
  security_warning(0);
else if (version == '12.2(27)SBA3')
  security_warning(0);
else if (version == '12.2(27)SBA4')
  security_warning(0);
else if (version == '12.2(27)SBA4')
  security_warning(0);
else if (version == '12.2(27)SBA5')
  security_warning(0);
else if (version == '12.2(27)SBA5')
  security_warning(0);
else if (version == '12.2(27)SBA6')
  security_warning(0);
else if (version == '12.2(27)SBA6')
  security_warning(0);
else if (version == '12.2(27)SBB')
  security_warning(0);
else if (version == '12.2(27)SBB')
  security_warning(0);
else if (version == '12.2(27)SBB1')
  security_warning(0);
else if (version == '12.2(27)SBB1')
  security_warning(0);
else if (version == '12.2(27)SBB2')
  security_warning(0);
else if (version == '12.2(27)SBB2')
  security_warning(0);
else if (version == '12.2(27)SBB2a')
  security_warning(0);
else if (version == '12.2(27)SBB2a')
  security_warning(0);
else if (version == '12.2(27)SBB3')
  security_warning(0);
else if (version == '12.2(27)SBB3')
  security_warning(0);
else if (version == '12.2(27)SBB4')
  security_warning(0);
else if (version == '12.2(27)SBB4')
  security_warning(0);
else if (version == '12.2(27)SBB4a')
  security_warning(0);
else if (version == '12.2(27)SBB4a')
  security_warning(0);
else if (version == '12.2(27)SBB4b')
  security_warning(0);
else if (version == '12.2(27)SBB4b')
  security_warning(0);
else if (version == '12.2(27)SBB4c')
  security_warning(0);
else if (version == '12.2(27)SBB4c')
  security_warning(0);
else if (version == '12.2(27)SBB4d')
  security_warning(0);
else if (version == '12.2(27)SBB4d')
  security_warning(0);
else if (version == '12.2(27)SBB5')
  security_warning(0);
else if (version == '12.2(27)SBB5')
  security_warning(0);
else if (version == '12.2(27)SBB6')
  security_warning(0);
else if (version == '12.2(27)SBB6')
  security_warning(0);
else if (version == '12.2(27)SBB6a')
  security_warning(0);
else if (version == '12.2(27)SBB6a')
  security_warning(0);
else if (version == '12.2(27)SBB7')
  security_warning(0);
else if (version == '12.2(27)SBB7')
  security_warning(0);
else if (version == '12.2(27)SBB8')
  security_warning(0);
else if (version == '12.2(27)SBB8')
  security_warning(0);
else if (version == '12.2(27)SBB9')
  security_warning(0);
else if (version == '12.2(27)SBB9')
  security_warning(0);
else if (version == '12.2(27)SBC')
  security_warning(0);
else if (version == '12.2(27)SBC')
  security_warning(0);
else if (version == '12.2(27)SBC1')
  security_warning(0);
else if (version == '12.2(27)SBC1')
  security_warning(0);
else if (version == '12.2(27)SBC2')
  security_warning(0);
else if (version == '12.2(27)SBC2')
  security_warning(0);
else if (version == '12.2(27)SBC3')
  security_warning(0);
else if (version == '12.2(27)SBC3')
  security_warning(0);
else if (version == '12.2(27)SBC4')
  security_warning(0);
else if (version == '12.2(27)SBC4')
  security_warning(0);
else if (version == '12.2(27)SBC5')
  security_warning(0);
else if (version == '12.2(27)SBC5')
  security_warning(0);
else if (version == '12.2(27)SBKA1')
  security_warning(0);
else if (version == '12.2(27)SBKA1')
  security_warning(0);
else if (version == '12.2(27)SBKA2')
  security_warning(0);
else if (version == '12.2(27)SBKA2')
  security_warning(0);
else if (version == '12.2(27)SBKA3')
  security_warning(0);
else if (version == '12.2(27)SBKA3')
  security_warning(0);
else if (version == '12.2(27)SBKA4')
  security_warning(0);
else if (version == '12.2(27)SBKA4')
  security_warning(0);
else if (version == '12.2(27)SBKA5')
  security_warning(0);
else if (version == '12.2(27)SBKA5')
  security_warning(0);
else if (version == '12.2(27)SBKB')
  security_warning(0);
else if (version == '12.2(27)SBKB')
  security_warning(0);
else if (version == '12.2(27)SBKB1')
  security_warning(0);
else if (version == '12.2(27)SBKB1')
  security_warning(0);
else if (version == '12.2(27)SBKB10')
  security_warning(0);
else if (version == '12.2(27)SBKB10')
  security_warning(0);
else if (version == '12.2(27)SBKB2')
  security_warning(0);
else if (version == '12.2(27)SBKB2')
  security_warning(0);
else if (version == '12.2(27)SBKB3')
  security_warning(0);
else if (version == '12.2(27)SBKB3')
  security_warning(0);
else if (version == '12.2(27)SBKB4')
  security_warning(0);
else if (version == '12.2(27)SBKB4')
  security_warning(0);
else if (version == '12.2(27)SBKB5')
  security_warning(0);
else if (version == '12.2(27)SBKB5')
  security_warning(0);
else if (version == '12.2(27)SBKB6')
  security_warning(0);
else if (version == '12.2(27)SBKB6')
  security_warning(0);
else if (version == '12.2(27)SBKB8')
  security_warning(0);
else if (version == '12.2(27)SBKB8')
  security_warning(0);
else if (version == '12.2(27)SBKB9')
  security_warning(0);
else if (version == '12.2(27)SBKB9')
  security_warning(0);
else if (version == '12.2(27)SV')
  security_warning(0);
else if (version == '12.2(27)SV1')
  security_warning(0);
else if (version == '12.2(27)SV2')
  security_warning(0);
else if (version == '12.2(27)SV3')
  security_warning(0);
else if (version == '12.2(27)SV4')
  security_warning(0);
else if (version == '12.2(27)SV5')
  security_warning(0);
else if (version == '12.2(27)TEST2')
  security_warning(0);
else if (version == '12.2(27)TEST2')
  security_warning(0);
else if (version == '12.2(27)TST11')
  security_warning(0);
else if (version == '12.2(27)TST11')
  security_warning(0);
else if (version == '12.2(27)TST8')
  security_warning(0);
else if (version == '12.2(27)TST8')
  security_warning(0);
else if (version == '12.2(27)UZ')
  security_warning(0);
else if (version == '12.2(27)UZ1')
  security_warning(0);
else if (version == '12.2(28a)ZV1')
  security_warning(0);
else if (version == '12.2(28b)ZV1')
  security_warning(0);
else if (version == '12.2(28)FSU')
  security_warning(0);
else if (version == '12.2(28)FSU')
  security_warning(0);
else if (version == '12.2(28)SB10')
  security_warning(0);
else if (version == '12.2(28)SB11')
  security_warning(0);
else if (version == '12.2(28)SB12')
  security_warning(0);
else if (version == '12.2(28)SB13')
  security_warning(0);
else if (version == '12.2(28)SB5c')
  security_warning(0);
else if (version == '12.2(28)SB6')
  security_warning(0);
else if (version == '12.2(28)SB7')
  security_warning(0);
else if (version == '12.2(28)SB8')
  security_warning(0);
else if (version == '12.2(28)SB9')
  security_warning(0);
else if (version == '12.2(28)SV')
  security_warning(0);
else if (version == '12.2(28)SV1')
  security_warning(0);
else if (version == '12.2(28)SV2')
  security_warning(0);
else if (version == '12.2(28)VZ')
  security_warning(0);
else if (version == '12.2(28)VZ1')
  security_warning(0);
else if (version == '12.2(28)ZV')
  security_warning(0);
else if (version == '12.2(28)ZV1')
  security_warning(0);
else if (version == '12.2(28)ZV2')
  security_warning(0);
else if (version == '12.2(28)ZX')
  security_warning(0);
else if (version == '12.2(29a)SV')
  security_warning(0);
else if (version == '12.2(29a)SV1')
  security_warning(0);
else if (version == '12.2(29b)SV')
  security_warning(0);
else if (version == '12.2(29b)SV1')
  security_warning(0);
else if (version == '12.2(29)SM')
  security_warning(0);
else if (version == '12.2(29)SM1')
  security_warning(0);
else if (version == '12.2(29)SM2')
  security_warning(0);
else if (version == '12.2(29)SM3')
  security_warning(0);
else if (version == '12.2(29)SM4')
  security_warning(0);
else if (version == '12.2(29)SM5')
  security_warning(0);
else if (version == '12.2(29)SM6')
  security_warning(0);
else if (version == '12.2(29)SM7')
  security_warning(0);
else if (version == '12.2(29)SV')
  security_warning(0);
else if (version == '12.2(29)SV1')
  security_warning(0);
else if (version == '12.2(29)SV2')
  security_warning(0);
else if (version == '12.2(29)SV3')
  security_warning(0);
else if (version == '12.2(29)SVA2')
  security_warning(0);
else if (version == '12.2(29)SVA2')
  security_warning(0);
else if (version == '12.2(2)SBT112')
  security_warning(0);
else if (version == '12.2(31a)XN2')
  security_warning(0);
else if (version == '12.2(31a)XN3')
  security_warning(0);
else if (version == '12.2(31b)XN2')
  security_warning(0);
else if (version == '12.2(31b)XN3')
  security_warning(0);
else if (version == '12.2(31c)XN2')
  security_warning(0);
else if (version == '12.2(31c)XN3')
  security_warning(0);
else if (version == '12.2(31r)SB')
  security_warning(0);
else if (version == '12.2(31r)SB1')
  security_warning(0);
else if (version == '12.2(31r)SB12')
  security_warning(0);
else if (version == '12.2(31r)SB13')
  security_warning(0);
else if (version == '12.2(31r)SB2')
  security_warning(0);
else if (version == '12.2(31r)SB9a')
  security_warning(0);
else if (version == '12.2(31)SB')
  security_warning(0);
else if (version == '12.2(31)SB1')
  security_warning(0);
else if (version == '12.2(31)SB10')
  security_warning(0);
else if (version == '12.2(31)SB10a')
  security_warning(0);
else if (version == '12.2(31)SB10b')
  security_warning(0);
else if (version == '12.2(31)SB10c')
  security_warning(0);
else if (version == '12.2(31)SB10d')
  security_warning(0);
else if (version == '12.2(31)SB10e')
  security_warning(0);
else if (version == '12.2(31)SB11')
  security_warning(0);
else if (version == '12.2(31)SB11a')
  security_warning(0);
else if (version == '12.2(31)SB11b')
  security_warning(0);
else if (version == '12.2(31)SB12')
  security_warning(0);
else if (version == '12.2(31)SB12a')
  security_warning(0);
else if (version == '12.2(31)SB13')
  security_warning(0);
else if (version == '12.2(31)SB13d')
  security_warning(0);
else if (version == '12.2(31)SB13f')
  security_warning(0);
else if (version == '12.2(31)SB13g')
  security_warning(0);
else if (version == '12.2(31)SB14')
  security_warning(0);
else if (version == '12.2(31)SB15')
  security_warning(0);
else if (version == '12.2(31)SB16')
  security_warning(0);
else if (version == '12.2(31)SB17')
  security_warning(0);
else if (version == '12.2(31)SB18')
  security_warning(0);
else if (version == '12.2(31)SB19')
  security_warning(0);
else if (version == '12.2(31)SB1a')
  security_warning(0);
else if (version == '12.2(31)SB1b')
  security_warning(0);
else if (version == '12.2(31)SB1c')
  security_warning(0);
else if (version == '12.2(31)SB1d')
  security_warning(0);
else if (version == '12.2(31)SB1e')
  security_warning(0);
else if (version == '12.2(31)SB1f')
  security_warning(0);
else if (version == '12.2(31)SB1g')
  security_warning(0);
else if (version == '12.2(31)SB2')
  security_warning(0);
else if (version == '12.2(31)SB20')
  security_warning(0);
else if (version == '12.2(31)SB21')
  security_warning(0);
else if (version == '12.2(31)SB2a')
  security_warning(0);
else if (version == '12.2(31)SB3')
  security_warning(0);
else if (version == '12.2(31)SB3a')
  security_warning(0);
else if (version == '12.2(31)SB3b')
  security_warning(0);
else if (version == '12.2(31)SB3c')
  security_warning(0);
else if (version == '12.2(31)SB3x')
  security_warning(0);
else if (version == '12.2(31)SB4')
  security_warning(0);
else if (version == '12.2(31)SB4a')
  security_warning(0);
else if (version == '12.2(31)SB5')
  security_warning(0);
else if (version == '12.2(31)SB5a')
  security_warning(0);
else if (version == '12.2(31)SB6')
  security_warning(0);
else if (version == '12.2(31)SB7')
  security_warning(0);
else if (version == '12.2(31)SB8')
  security_warning(0);
else if (version == '12.2(31)SB8a')
  security_warning(0);
else if (version == '12.2(31)SB9')
  security_warning(0);
else if (version == '12.2(31)SB9a')
  security_warning(0);
else if (version == '12.2(31)SB9b')
  security_warning(0);
else if (version == '12.2(31)SBY')
  security_warning(0);
else if (version == '12.2(31)SBY')
  security_warning(0);
else if (version == '12.2(31)SBY1')
  security_warning(0);
else if (version == '12.2(31)SBY1')
  security_warning(0);
else if (version == '12.2(31)SG')
  security_warning(0);
else if (version == '12.2(31)SG1')
  security_warning(0);
else if (version == '12.2(31)SG2')
  security_warning(0);
else if (version == '12.2(31)SG3')
  security_warning(0);
else if (version == '12.2(31)SGA')
  security_warning(0);
else if (version == '12.2(31)SGA')
  security_warning(0);
else if (version == '12.2(31)SGA1')
  security_warning(0);
else if (version == '12.2(31)SGA1')
  security_warning(0);
else if (version == '12.2(31)SGA10')
  security_warning(0);
else if (version == '12.2(31)SGA11')
  security_warning(0);
else if (version == '12.2(31)SGA2')
  security_warning(0);
else if (version == '12.2(31)SGA2')
  security_warning(0);
else if (version == '12.2(31)SGA3')
  security_warning(0);
else if (version == '12.2(31)SGA3')
  security_warning(0);
else if (version == '12.2(31)SGA4')
  security_warning(0);
else if (version == '12.2(31)SGA4')
  security_warning(0);
else if (version == '12.2(31)SGA5')
  security_warning(0);
else if (version == '12.2(31)SGA5')
  security_warning(0);
else if (version == '12.2(31)SGA6')
  security_warning(0);
else if (version == '12.2(31)SGA6')
  security_warning(0);
else if (version == '12.2(31)SGA7')
  security_warning(0);
else if (version == '12.2(31)SGA7')
  security_warning(0);
else if (version == '12.2(31)SGA8')
  security_warning(0);
else if (version == '12.2(31)SGA8')
  security_warning(0);
else if (version == '12.2(31)SGA9')
  security_warning(0);
else if (version == '12.2(31)TST5')
  security_warning(0);
else if (version == '12.2(31)TST5')
  security_warning(0);
else if (version == '12.2(31)XN')
  security_warning(0);
else if (version == '12.2(31)XN1')
  security_warning(0);
else if (version == '12.2(31)XN2')
  security_warning(0);
else if (version == '12.2(31)XN3')
  security_warning(0);
else if (version == '12.2(31)ZV')
  security_warning(0);
else if (version == '12.2(31)ZV0a')
  security_warning(0);
else if (version == '12.2(31)ZV0b')
  security_warning(0);
else if (version == '12.2(31)ZV0c')
  security_warning(0);
else if (version == '12.2(31)ZV0d')
  security_warning(0);
else if (version == '12.2(31)ZV0e')
  security_warning(0);
else if (version == '12.2(31)ZV0f')
  security_warning(0);
else if (version == '12.2(31)ZV0g')
  security_warning(0);
else if (version == '12.2(31)ZV0h')
  security_warning(0);
else if (version == '12.2(31)ZV0i')
  security_warning(0);
else if (version == '12.2(31)ZV0j')
  security_warning(0);
else if (version == '12.2(31)ZV1a')
  security_warning(0);
else if (version == '12.2(31)ZV1b')
  security_warning(0);
else if (version == '12.2(31)ZV1c')
  security_warning(0);
else if (version == '12.2(31)ZV2')
  security_warning(0);
else if (version == '12.2(31)ZV2a')
  security_warning(0);
else if (version == '12.2(31)ZV2b')
  security_warning(0);
else if (version == '12.2(31)ZV2c')
  security_warning(0);
else if (version == '12.2(33r)SRB')
  security_warning(0);
else if (version == '12.2(33r)SRB')
  security_warning(0);
else if (version == '12.2(33r)SRB1')
  security_warning(0);
else if (version == '12.2(33r)SRB1')
  security_warning(0);
else if (version == '12.2(33r)SRB2')
  security_warning(0);
else if (version == '12.2(33r)SRB2')
  security_warning(0);
else if (version == '12.2(33r)SRB3')
  security_warning(0);
else if (version == '12.2(33r)SRB3')
  security_warning(0);
else if (version == '12.2(33r)SRB4')
  security_warning(0);
else if (version == '12.2(33r)SRB4')
  security_warning(0);
else if (version == '12.2(33r)SRC')
  security_warning(0);
else if (version == '12.2(33r)SRC')
  security_warning(0);
else if (version == '12.2(33r)SRC1')
  security_warning(0);
else if (version == '12.2(33r)SRC1')
  security_warning(0);
else if (version == '12.2(33r)SRC2')
  security_warning(0);
else if (version == '12.2(33r)SRC2')
  security_warning(0);
else if (version == '12.2(33r)XN')
  security_warning(0);
else if (version == '12.2(33r)XN1')
  security_warning(0);
else if (version == '12.2(33r)XN2')
  security_warning(0);
else if (version == '12.2(33)SRA')
  security_warning(0);
else if (version == '12.2(33)SRA')
  security_warning(0);
else if (version == '12.2(33)SRA1')
  security_warning(0);
else if (version == '12.2(33)SRA1')
  security_warning(0);
else if (version == '12.2(33)SRA2')
  security_warning(0);
else if (version == '12.2(33)SRA2')
  security_warning(0);
else if (version == '12.2(33)SRA3')
  security_warning(0);
else if (version == '12.2(33)SRA3')
  security_warning(0);
else if (version == '12.2(33)SRA4')
  security_warning(0);
else if (version == '12.2(33)SRA4')
  security_warning(0);
else if (version == '12.2(33)SRA5')
  security_warning(0);
else if (version == '12.2(33)SRA5')
  security_warning(0);
else if (version == '12.2(33)SRA6')
  security_warning(0);
else if (version == '12.2(33)SRA6')
  security_warning(0);
else if (version == '12.2(33)SRA7')
  security_warning(0);
else if (version == '12.2(33)SRA7')
  security_warning(0);
else if (version == '12.2(33)SRB')
  security_warning(0);
else if (version == '12.2(33)SRB')
  security_warning(0);
else if (version == '12.2(33)SRB1')
  security_warning(0);
else if (version == '12.2(33)SRB1')
  security_warning(0);
else if (version == '12.2(33)SRB2')
  security_warning(0);
else if (version == '12.2(33)SRB2')
  security_warning(0);
else if (version == '12.2(33)SRB3')
  security_warning(0);
else if (version == '12.2(33)SRB4')
  security_warning(0);
else if (version == '12.2(33)SRB5')
  security_warning(0);
else if (version == '12.2(33)SRB5a')
  security_warning(0);
else if (version == '12.2(33)SRB6')
  security_warning(0);
else if (version == '12.2(33)SRB7')
  security_warning(0);
else if (version == '12.2(33)STE0')
  security_warning(0);
else if (version == '12.2(33)STE1')
  security_warning(0);
else if (version == '12.2(33)SXH')
  security_warning(0);
else if (version == '12.2(33)SXH')
  security_warning(0);
else if (version == '12.2(33)SXH0a')
  security_warning(0);
else if (version == '12.2(33)SXH0a')
  security_warning(0);
else if (version == '12.2(33)XN')
  security_warning(0);
else if (version == '12.2(33)XN1')
  security_warning(0);
else if (version == '12.2(33)XN2')
  security_warning(0);
else if (version == '12.2(33)XN3')
  security_warning(0);
else if (version == '12.2(33)ZW')
  security_warning(0);
else if (version == '12.2(35)SE')
  security_warning(0);
else if (version == '12.2(35)SE1')
  security_warning(0);
else if (version == '12.2(35)SE2')
  security_warning(0);
else if (version == '12.2(35)SE3')
  security_warning(0);
else if (version == '12.2(35)SE4')
  security_warning(0);
else if (version == '12.2(35)SE5')
  security_warning(0);
else if (version == '12.2(37)SE')
  security_warning(0);
else if (version == '12.2(37)SE1')
  security_warning(0);
else if (version == '12.2(37)SG')
  security_warning(0);
else if (version == '12.2(37)SG1')
  security_warning(0);
else if (version == '12.2(3)SBT112')
  security_warning(0);
else if (version == '12.2(40r)SG')
  security_warning(0);
else if (version == '12.2(40)SE')
  security_warning(0);
else if (version == '12.2(40)SE1')
  security_warning(0);
else if (version == '12.2(40)SE2')
  security_warning(0);
else if (version == '12.2(40)SG')
  security_warning(0);
else if (version == '12.2(40)XO')
  security_warning(0);
else if (version == '12.2(44)SE')
  security_warning(0);
else if (version == '12.2(44)SE1')
  security_warning(0);
else if (version == '12.2(44)SG')
  security_warning(0);
else if (version == '12.2(44)SG1')
  security_warning(0);
else if (version == '12.2(44)SQ')
  security_warning(0);
else if (version == '12.2(44)SQ1')
  security_warning(0);
else if (version == '12.2(44)SQ2')
  security_warning(0);
else if (version == '12.2(44)SQ20081109')
  security_warning(0);
else if (version == '12.2(44)SQ20081110')
  security_warning(0);
else if (version == '12.2(44)SQ20081111')
  security_warning(0);
else if (version == '12.2(44)SQ20081115')
  security_warning(0);
else if (version == '12.2(44)SQ20081122')
  security_warning(0);
else if (version == '12.2(44)SQ20081124')
  security_warning(0);
else if (version == '12.2(44)SQ20081129')
  security_warning(0);
else if (version == '12.2(44)SQ20081201')
  security_warning(0);
else if (version == '12.2(44)SQ20081206')
  security_warning(0);
else if (version == '12.2(44)SQ20081208')
  security_warning(0);
else if (version == '12.2(44)SQ20081213')
  security_warning(0);
else if (version == '12.2(44)SQ20090114')
  security_warning(0);
else if (version == '12.2(44)SQ20090116')
  security_warning(0);
else if (version == '12.2(44)SQ20090123')
  security_warning(0);
else if (version == '12.2(44)SQ20090128')
  security_warning(0);
else if (version == '12.2(44)SQ20090130')
  security_warning(0);
else if (version == '12.2(44)SQ20090227')
  security_warning(0);
else if (version == '12.2(44)SQ20090327')
  security_warning(0);
else if (version == '12.2(44)SQ20090330')
  security_warning(0);
else if (version == '12.2(44)SQ20090331')
  security_warning(0);
else if (version == '12.2(44)SQ20090401')
  security_warning(0);
else if (version == '12.2(44)SQ20090402')
  security_warning(0);
else if (version == '12.2(44)SQ20090430')
  security_warning(0);
else if (version == '12.2(44)SQ20090710')
  security_warning(0);
else if (version == '12.2(44)SQ20090731')
  security_warning(0);
else if (version == '12.2(44)SQ20090807')
  security_warning(0);
else if (version == '12.2(46)SG')
  security_warning(0);
else if (version == '12.2(46)SG1')
  security_warning(0);
else if (version == '12.2(4)SBT112')
  security_warning(0);
else if (version == '12.2(5)SBT112')
  security_warning(0);
else if (version == '12.2(6c)TEST')
  security_warning(0);
else if (version == '12.2(73)TST')
  security_warning(0);
else if (version == '12.2(73)TST')
  security_warning(0);
else if (version == '12.2(7)SBT112')
  security_warning(0);
else if (version == '12.2(8)SBT112')
  security_warning(0);
else if (version == '12.2(8)TPC10a')
  security_warning(0);
else if (version == '12.2(8)TPC10b')
  security_warning(0);
else if (version == '12.2(8)TPC10c')
  security_warning(0);
else if (version == '12.2(92)TST')
  security_warning(0);
else if (version == '12.2(92)TST1')
  security_warning(0);
else if (version == '12.2(92)TST2')
  security_warning(0);
else if (version == '12.2(9909)TEST')
  security_warning(0);
else if (version == '12.2(9909)TEST')
  security_warning(0);
else if (version == '12.2(9999)SRA')
  security_warning(0);
else if (version == '12.2(9999)SRA')
  security_warning(0);
else if (version == '12.2(9999)SRA2')
  security_warning(0);
else if (version == '12.2(9999)SRA2')
  security_warning(0);
else if (version == '12.2(99)SX1003')
  security_warning(0);
else if (version == '12.2(99)SX1004')
  security_warning(0);
else if (version == '12.2(99)SX1005')
  security_warning(0);
else if (version == '12.2(99)SX1006')
  security_warning(0);
else if (version == '12.2(99)SX1007')
  security_warning(0);
else if (version == '12.2(99)SX1008')
  security_warning(0);
else if (version == '12.2(99)SX1009')
  security_warning(0);
else if (version == '12.2(99)SX1010')
  security_warning(0);
else if (version == '12.2(99)SX1011')
  security_warning(0);
else if (version == '12.2(99)SX1012')
  security_warning(0);
else if (version == '12.2(99)SX1013')
  security_warning(0);
else if (version == '12.2(99)SX1014')
  security_warning(0);
else if (version == '12.2(99)SX1015')
  security_warning(0);
else if (version == '12.2(99)SX1016')
  security_warning(0);
else if (version == '12.2(99)SX1017')
  security_warning(0);
else if (version == '12.2(99)SX1018')
  security_warning(0);
else if (version == '12.2(99)SX1019')
  security_warning(0);
else if (version == '12.2(99)SX1020')
  security_warning(0);
else if (version == '12.2(99)SX1021')
  security_warning(0);
else if (version == '12.2(99)SX1022')
  security_warning(0);
else if (version == '12.2(99)SX1023')
  security_warning(0);
else if (version == '12.2(99)SX1024')
  security_warning(0);
else if (version == '12.2(99)SX1025')
  security_warning(0);
else if (version == '12.2(99)SX1026')
  security_warning(0);
else if (version == '12.2(99)SX1027')
  security_warning(0);
else if (version == '12.2(99)SX1028')
  security_warning(0);
else if (version == '12.2(99)SX1029')
  security_warning(0);
else if (version == '12.2(99)SX1031')
  security_warning(0);
else if (version == '12.2(99)SX1031a')
  security_warning(0);
else if (version == '12.2(99)SX1032')
  security_warning(0);
else if (version == '12.2(99)SX1033')
  security_warning(0);
else if (version == '12.2(99)SX1034')
  security_warning(0);
else if (version == '12.2(99)SX1035')
  security_warning(0);
else if (version == '12.2(99)SX2000')
  security_warning(0);
else if (version == '12.2(99)SX2001')
  security_warning(0);
else if (version == '12.2(99)SX2002')
  security_warning(0);
else if (version == '12.2(99)SX2003')
  security_warning(0);
else if (version == '12.2(99)SX2004')
  security_warning(0);
else if (version == '12.2(99)TEST2')
  security_warning(0);
else if (version == '12.2(99)TEST2')
  security_warning(0);
else if (version == '12.2(9)SBT112')
  security_warning(0);
else if (version == '12.2(9)YE')
  security_warning(0);
else if (version == '12.2(9)YO')
  security_warning(0);
else if (version == '12.2(9)YO1')
  security_warning(0);
else if (version == '12.2(9)YO2')
  security_warning(0);
else if (version == '12.2(9)YO3')
  security_warning(0);
else if (version == '12.2(9)YO4')
  security_warning(0);
else if (version == '12.2(9)ZA')
  security_warning(0);
else if (version == '12.3(1)')
  security_warning(0);
else if (version == '12.3(10)')
  security_warning(0);
else if (version == '12.3(10a)')
  security_warning(0);
else if (version == '12.3(10a)M0')
  security_warning(0);
else if (version == '12.3(10b)')
  security_warning(0);
else if (version == '12.3(10c)')
  security_warning(0);
else if (version == '12.3(10d)')
  security_warning(0);
else if (version == '12.3(10e)')
  security_warning(0);
else if (version == '12.3(10f)')
  security_warning(0);
else if (version == '12.3(10r)')
  security_warning(0);
else if (version == '12.3(11)JA')
  security_warning(0);
else if (version == '12.3(11)JA1')
  security_warning(0);
else if (version == '12.3(11)JA2')
  security_warning(0);
else if (version == '12.3(11)JA3')
  security_warning(0);
else if (version == '12.3(11)JA4')
  security_warning(0);
else if (version == '12.3(11)JX')
  security_warning(0);
else if (version == '12.3(11)JX1')
  security_warning(0);
else if (version == '12.3(11r)T')
  security_warning(0);
else if (version == '12.3(11r)T1')
  security_warning(0);
else if (version == '12.3(11r)T2')
  security_warning(0);
else if (version == '12.3(11)T')
  security_warning(0);
else if (version == '12.3(11)T1')
  security_warning(0);
else if (version == '12.3(11)T10')
  security_warning(0);
else if (version == '12.3(11)T11')
  security_warning(0);
else if (version == '12.3(11)T12')
  security_warning(0);
else if (version == '12.3(11)T2')
  security_warning(0);
else if (version == '12.3(11)T2a')
  security_warning(0);
else if (version == '12.3(11)T3')
  security_warning(0);
else if (version == '12.3(11)T4')
  security_warning(0);
else if (version == '12.3(11)T5')
  security_warning(0);
else if (version == '12.3(11)T6')
  security_warning(0);
else if (version == '12.3(11)T7')
  security_warning(0);
else if (version == '12.3(11)T8')
  security_warning(0);
else if (version == '12.3(11)T9')
  security_warning(0);
else if (version == '12.3(11)TO3')
  security_warning(0);
else if (version == '12.3(11)XL')
  security_warning(0);
else if (version == '12.3(11)XL1')
  security_warning(0);
else if (version == '12.3(11)XL2')
  security_warning(0);
else if (version == '12.3(11)XL3')
  security_warning(0);
else if (version == '12.3(11)YF')
  security_warning(0);
else if (version == '12.3(11)YF1')
  security_warning(0);
else if (version == '12.3(11)YF2')
  security_warning(0);
else if (version == '12.3(11)YF3')
  security_warning(0);
else if (version == '12.3(11)YF4')
  security_warning(0);
else if (version == '12.3(11)YJ')
  security_warning(0);
else if (version == '12.3(11)YK')
  security_warning(0);
else if (version == '12.3(11)YK1')
  security_warning(0);
else if (version == '12.3(11)YK2')
  security_warning(0);
else if (version == '12.3(11)YK3')
  security_warning(0);
else if (version == '12.3(11)YL')
  security_warning(0);
else if (version == '12.3(11)YL1')
  security_warning(0);
else if (version == '12.3(11)YL2')
  security_warning(0);
else if (version == '12.3(11)YN')
  security_warning(0);
else if (version == '12.3(11)YR')
  security_warning(0);
else if (version == '12.3(11)YR1')
  security_warning(0);
else if (version == '12.3(11)YS')
  security_warning(0);
else if (version == '12.3(11)YS')
  security_warning(0);
else if (version == '12.3(11)YS1')
  security_warning(0);
else if (version == '12.3(11)YS1')
  security_warning(0);
else if (version == '12.3(11)YS2')
  security_warning(0);
else if (version == '12.3(11)YS2')
  security_warning(0);
else if (version == '12.3(11)YW')
  security_warning(0);
else if (version == '12.3(11)YW1')
  security_warning(0);
else if (version == '12.3(11)YW2')
  security_warning(0);
else if (version == '12.3(11)YW3')
  security_warning(0);
else if (version == '12.3(11)YZ')
  security_warning(0);
else if (version == '12.3(11)YZ1')
  security_warning(0);
else if (version == '12.3(11)YZ2')
  security_warning(0);
else if (version == '12.3(11)ZB')
  security_warning(0);
else if (version == '12.3(11)ZB1')
  security_warning(0);
else if (version == '12.3(11)ZB2')
  security_warning(0);
else if (version == '12.3(12)')
  security_warning(0);
else if (version == '12.3(12a)')
  security_warning(0);
else if (version == '12.3(12b)')
  security_warning(0);
else if (version == '12.3(12c)')
  security_warning(0);
else if (version == '12.3(12d)')
  security_warning(0);
else if (version == '12.3(12e)')
  security_warning(0);
else if (version == '12.3(12r)T')
  security_warning(0);
else if (version == '12.3(12r)T1')
  security_warning(0);
else if (version == '12.3(12r)T2')
  security_warning(0);
else if (version == '12.3(13)')
  security_warning(0);
else if (version == '12.3(13a)')
  security_warning(0);
else if (version == '12.3(13a)BC')
  security_warning(0);
else if (version == '12.3(13a)BC1')
  security_warning(0);
else if (version == '12.3(13a)BC2')
  security_warning(0);
else if (version == '12.3(13a)BC3')
  security_warning(0);
else if (version == '12.3(13a)BC4')
  security_warning(0);
else if (version == '12.3(13a)BC5')
  security_warning(0);
else if (version == '12.3(13a)BC6')
  security_warning(0);
else if (version == '12.3(13b)')
  security_warning(0);
else if (version == '12.3(14r)T')
  security_warning(0);
else if (version == '12.3(14r)T')
  security_warning(0);
else if (version == '12.3(14r)T1')
  security_warning(0);
else if (version == '12.3(14r)T1')
  security_warning(0);
else if (version == '12.3(14)T')
  security_warning(0);
else if (version == '12.3(14)T1')
  security_warning(0);
else if (version == '12.3(14)T2')
  security_warning(0);
else if (version == '12.3(14)T3')
  security_warning(0);
else if (version == '12.3(14)T4')
  security_warning(0);
else if (version == '12.3(14)T5')
  security_warning(0);
else if (version == '12.3(14)T6')
  security_warning(0);
else if (version == '12.3(14)T7')
  security_warning(0);
else if (version == '12.3(14)YM')
  security_warning(0);
else if (version == '12.3(14)YM0707')
  security_warning(0);
else if (version == '12.3(14)YM1')
  security_warning(0);
else if (version == '12.3(14)YM10')
  security_warning(0);
else if (version == '12.3(14)YM11')
  security_warning(0);
else if (version == '12.3(14)YM12')
  security_warning(0);
else if (version == '12.3(14)YM2')
  security_warning(0);
else if (version == '12.3(14)YM3')
  security_warning(0);
else if (version == '12.3(14)YM4')
  security_warning(0);
else if (version == '12.3(14)YM5')
  security_warning(0);
else if (version == '12.3(14)YM6')
  security_warning(0);
else if (version == '12.3(14)YM7')
  security_warning(0);
else if (version == '12.3(14)YM8')
  security_warning(0);
else if (version == '12.3(14)YM9')
  security_warning(0);
else if (version == '12.3(14)YQ')
  security_warning(0);
else if (version == '12.3(14)YQ051806')
  security_warning(0);
else if (version == '12.3(14)YQ1')
  security_warning(0);
else if (version == '12.3(14)YQ2')
  security_warning(0);
else if (version == '12.3(14)YQ3')
  security_warning(0);
else if (version == '12.3(14)YQ4')
  security_warning(0);
else if (version == '12.3(14)YQ5')
  security_warning(0);
else if (version == '12.3(14)YQ6')
  security_warning(0);
else if (version == '12.3(14)YQ7')
  security_warning(0);
else if (version == '12.3(14)YQ8')
  security_warning(0);
else if (version == '12.3(14)YT')
  security_warning(0);
else if (version == '12.3(14)YT')
  security_warning(0);
else if (version == '12.3(14)YT1')
  security_warning(0);
else if (version == '12.3(14)YT1')
  security_warning(0);
else if (version == '12.3(14)YU')
  security_warning(0);
else if (version == '12.3(14)YU1')
  security_warning(0);
else if (version == '12.3(14)YX')
  security_warning(0);
else if (version == '12.3(14)YX1')
  security_warning(0);
else if (version == '12.3(14)YX10')
  security_warning(0);
else if (version == '12.3(14)YX11')
  security_warning(0);
else if (version == '12.3(14)YX2')
  security_warning(0);
else if (version == '12.3(14)YX3')
  security_warning(0);
else if (version == '12.3(14)YX4')
  security_warning(0);
else if (version == '12.3(14)YX5')
  security_warning(0);
else if (version == '12.3(14)YX7')
  security_warning(0);
else if (version == '12.3(14)YX8')
  security_warning(0);
else if (version == '12.3(14)YX9')
  security_warning(0);
else if (version == '12.3(15)')
  security_warning(0);
else if (version == '12.3(15a)')
  security_warning(0);
else if (version == '12.3(15b)')
  security_warning(0);
else if (version == '12.3(16)')
  security_warning(0);
else if (version == '12.3(16a)')
  security_warning(0);
else if (version == '12.3(17)')
  security_warning(0);
else if (version == '12.3(17a)')
  security_warning(0);
else if (version == '12.3(17a)BC')
  security_warning(0);
else if (version == '12.3(17a)BC1')
  security_warning(0);
else if (version == '12.3(17a)BC2')
  security_warning(0);
else if (version == '12.3(17b)')
  security_warning(0);
else if (version == '12.3(17b)BC3')
  security_warning(0);
else if (version == '12.3(17b)BC4')
  security_warning(0);
else if (version == '12.3(17b)BC5')
  security_warning(0);
else if (version == '12.3(17b)BC6')
  security_warning(0);
else if (version == '12.3(17b)BC7')
  security_warning(0);
else if (version == '12.3(17b)BC8')
  security_warning(0);
else if (version == '12.3(17b)BC9')
  security_warning(0);
else if (version == '12.3(17c)')
  security_warning(0);
else if (version == '12.3(18)')
  security_warning(0);
else if (version == '12.3(18a)')
  security_warning(0);
else if (version == '12.3(18r)S1')
  security_warning(0);
else if (version == '12.3(18r)S1')
  security_warning(0);
else if (version == '12.3(18r)S2')
  security_warning(0);
else if (version == '12.3(18r)S2')
  security_warning(0);
else if (version == '12.3(18r)SX1')
  security_warning(0);
else if (version == '12.3(18r)SX1')
  security_warning(0);
else if (version == '12.3(19)')
  security_warning(0);
else if (version == '12.3(19a)')
  security_warning(0);
else if (version == '12.3(1a)')
  security_warning(0);
else if (version == '12.3(1a)B')
  security_warning(0);
else if (version == '12.3(1a)BW')
  security_warning(0);
else if (version == '12.3(1)FIPS140')
  security_warning(0);
else if (version == '12.3(1r)T')
  security_warning(0);
else if (version == '12.3(1r)T1')
  security_warning(0);
else if (version == '12.3(20)')
  security_warning(0);
else if (version == '12.3(20a)')
  security_warning(0);
else if (version == '12.3(21)')
  security_warning(0);
else if (version == '12.3(21a)')
  security_warning(0);
else if (version == '12.3(21a)BC1')
  security_warning(0);
else if (version == '12.3(21a)BC2')
  security_warning(0);
else if (version == '12.3(21a)BC3')
  security_warning(0);
else if (version == '12.3(21a)BC4')
  security_warning(0);
else if (version == '12.3(21a)BC5')
  security_warning(0);
else if (version == '12.3(21a)BC6')
  security_warning(0);
else if (version == '12.3(21b)')
  security_warning(0);
else if (version == '12.3(21)BC')
  security_warning(0);
else if (version == '12.3(22)')
  security_warning(0);
else if (version == '12.3(22a)')
  security_warning(0);
else if (version == '12.3(23)')
  security_warning(0);
else if (version == '12.3(23)BC')
  security_warning(0);
else if (version == '12.3(24)')
  security_warning(0);
else if (version == '12.3(24a)')
  security_warning(0);
else if (version == '12.3(2)JA')
  security_warning(0);
else if (version == '12.3(2)JA1')
  security_warning(0);
else if (version == '12.3(2)JA2')
  security_warning(0);
else if (version == '12.3(2)JA3')
  security_warning(0);
else if (version == '12.3(2)JA4')
  security_warning(0);
else if (version == '12.3(2)JA5')
  security_warning(0);
else if (version == '12.3(2)JA6')
  security_warning(0);
else if (version == '12.3(2)JK')
  security_warning(0);
else if (version == '12.3(2)JK1')
  security_warning(0);
else if (version == '12.3(2)JK2')
  security_warning(0);
else if (version == '12.3(2)JK3')
  security_warning(0);
else if (version == '12.3(2)JL')
  security_warning(0);
else if (version == '12.3(2)JL1')
  security_warning(0);
else if (version == '12.3(2)JL2')
  security_warning(0);
else if (version == '12.3(2)JL3')
  security_warning(0);
else if (version == '12.3(2)JL4')
  security_warning(0);
else if (version == '12.3(2l)JK')
  security_warning(0);
else if (version == '12.3(2l)JL')
  security_warning(0);
else if (version == '12.3(2)T')
  security_warning(0);
else if (version == '12.3(2)T1')
  security_warning(0);
else if (version == '12.3(2)T2')
  security_warning(0);
else if (version == '12.3(2)T3')
  security_warning(0);
else if (version == '12.3(2)T4')
  security_warning(0);
else if (version == '12.3(2)T5')
  security_warning(0);
else if (version == '12.3(2)T6')
  security_warning(0);
else if (version == '12.3(2)T7')
  security_warning(0);
else if (version == '12.3(2)T8')
  security_warning(0);
else if (version == '12.3(2)T9')
  security_warning(0);
else if (version == '12.3(2)XA')
  security_warning(0);
else if (version == '12.3(2)XA1')
  security_warning(0);
else if (version == '12.3(2)XA2')
  security_warning(0);
else if (version == '12.3(2)XA3')
  security_warning(0);
else if (version == '12.3(2)XA4')
  security_warning(0);
else if (version == '12.3(2)XA5')
  security_warning(0);
else if (version == '12.3(2)XA6')
  security_warning(0);
else if (version == '12.3(2)XC')
  security_warning(0);
else if (version == '12.3(2)XC1')
  security_warning(0);
else if (version == '12.3(2)XC2')
  security_warning(0);
else if (version == '12.3(2)XC3')
  security_warning(0);
else if (version == '12.3(2)XC4')
  security_warning(0);
else if (version == '12.3(2)XC5')
  security_warning(0);
else if (version == '12.3(2)XE')
  security_warning(0);
else if (version == '12.3(2)XE1')
  security_warning(0);
else if (version == '12.3(2)XE2')
  security_warning(0);
else if (version == '12.3(2)XE3')
  security_warning(0);
else if (version == '12.3(2)XE4')
  security_warning(0);
else if (version == '12.3(2)XE5')
  security_warning(0);
else if (version == '12.3(2)XF')
  security_warning(0);
else if (version == '12.3(2)XT')
  security_warning(0);
else if (version == '12.3(2)XT1')
  security_warning(0);
else if (version == '12.3(2)XT2')
  security_warning(0);
else if (version == '12.3(2)XT3')
  security_warning(0);
else if (version == '12.3(2)XZ')
  security_warning(0);
else if (version == '12.3(2)XZ1')
  security_warning(0);
else if (version == '12.3(2)XZ2')
  security_warning(0);
else if (version == '12.3(3)')
  security_warning(0);
else if (version == '12.3(3a)')
  security_warning(0);
else if (version == '12.3(3b)')
  security_warning(0);
else if (version == '12.3(3)B')
  security_warning(0);
else if (version == '12.3(3)B1')
  security_warning(0);
else if (version == '12.3(3c)')
  security_warning(0);
else if (version == '12.3(3d)')
  security_warning(0);
else if (version == '12.3(3e)')
  security_warning(0);
else if (version == '12.3(3f)')
  security_warning(0);
else if (version == '12.3(3f)SAVE')
  security_warning(0);
else if (version == '12.3(3g)')
  security_warning(0);
else if (version == '12.3(3h)')
  security_warning(0);
else if (version == '12.3(3i)')
  security_warning(0);
else if (version == '12.3(4)INF')
  security_warning(0);
else if (version == '12.3(4)JA')
  security_warning(0);
else if (version == '12.3(4)JA1')
  security_warning(0);
else if (version == '12.3(4)JA2')
  security_warning(0);
else if (version == '12.3(4r)T')
  security_warning(0);
else if (version == '12.3(4r)T1')
  security_warning(0);
else if (version == '12.3(4r)T2')
  security_warning(0);
else if (version == '12.3(4r)T3')
  security_warning(0);
else if (version == '12.3(4r)T4')
  security_warning(0);
else if (version == '12.3(4r)XD')
  security_warning(0);
else if (version == '12.3(4)T')
  security_warning(0);
else if (version == '12.3(4)T1')
  security_warning(0);
else if (version == '12.3(4)T10')
  security_warning(0);
else if (version == '12.3(4)T11')
  security_warning(0);
else if (version == '12.3(4)T12')
  security_warning(0);
else if (version == '12.3(4)T2')
  security_warning(0);
else if (version == '12.3(4)T2a')
  security_warning(0);
else if (version == '12.3(4)T3')
  security_warning(0);
else if (version == '12.3(4)T4')
  security_warning(0);
else if (version == '12.3(4)T5')
  security_warning(0);
else if (version == '12.3(4)T6')
  security_warning(0);
else if (version == '12.3(4)T7')
  security_warning(0);
else if (version == '12.3(4)T8')
  security_warning(0);
else if (version == '12.3(4)T9')
  security_warning(0);
else if (version == '12.3(4)TPC11a')
  security_warning(0);
else if (version == '12.3(4)TPC11b')
  security_warning(0);
else if (version == '12.3(4)XD')
  security_warning(0);
else if (version == '12.3(4)XD1')
  security_warning(0);
else if (version == '12.3(4)XD2')
  security_warning(0);
else if (version == '12.3(4)XD3')
  security_warning(0);
else if (version == '12.3(4)XD4')
  security_warning(0);
else if (version == '12.3(4)XG')
  security_warning(0);
else if (version == '12.3(4)XG1')
  security_warning(0);
else if (version == '12.3(4)XG2')
  security_warning(0);
else if (version == '12.3(4)XG3')
  security_warning(0);
else if (version == '12.3(4)XG4')
  security_warning(0);
else if (version == '12.3(4)XG5')
  security_warning(0);
else if (version == '12.3(4)XN')
  security_warning(0);
else if (version == '12.3(4)XN1')
  security_warning(0);
else if (version == '12.3(4)XN2')
  security_warning(0);
else if (version == '12.3(4)YE')
  security_warning(0);
else if (version == '12.3(4)YE1')
  security_warning(0);
else if (version == '12.3(5)')
  security_warning(0);
else if (version == '12.3(5a)')
  security_warning(0);
else if (version == '12.3(5a)B')
  security_warning(0);
else if (version == '12.3(5a)B0a')
  security_warning(0);
else if (version == '12.3(5a)B1')
  security_warning(0);
else if (version == '12.3(5a)B2')
  security_warning(0);
else if (version == '12.3(5a)B3')
  security_warning(0);
else if (version == '12.3(5a)B4')
  security_warning(0);
else if (version == '12.3(5a)B5')
  security_warning(0);
else if (version == '12.3(5b)')
  security_warning(0);
else if (version == '12.3(5c)')
  security_warning(0);
else if (version == '12.3(5d)')
  security_warning(0);
else if (version == '12.3(5e)')
  security_warning(0);
else if (version == '12.3(5f)')
  security_warning(0);
else if (version == '12.3(6)')
  security_warning(0);
else if (version == '12.3(6a)')
  security_warning(0);
else if (version == '12.3(6b)')
  security_warning(0);
else if (version == '12.3(6c)')
  security_warning(0);
else if (version == '12.3(6d)')
  security_warning(0);
else if (version == '12.3(6e)')
  security_warning(0);
else if (version == '12.3(6f)')
  security_warning(0);
else if (version == '12.3(6r)')
  security_warning(0);
else if (version == '12.3(7)JA')
  security_warning(0);
else if (version == '12.3(7)JA1')
  security_warning(0);
else if (version == '12.3(7)JA2')
  security_warning(0);
else if (version == '12.3(7)JA3')
  security_warning(0);
else if (version == '12.3(7)JA4')
  security_warning(0);
else if (version == '12.3(7)JA5')
  security_warning(0);
else if (version == '12.3(7)JX')
  security_warning(0);
else if (version == '12.3(7)JX1')
  security_warning(0);
else if (version == '12.3(7)JX10')
  security_warning(0);
else if (version == '12.3(7)JX2')
  security_warning(0);
else if (version == '12.3(7)JX3')
  security_warning(0);
else if (version == '12.3(7)JX4')
  security_warning(0);
else if (version == '12.3(7)JX5')
  security_warning(0);
else if (version == '12.3(7)JX6')
  security_warning(0);
else if (version == '12.3(7)JX7')
  security_warning(0);
else if (version == '12.3(7)JX8')
  security_warning(0);
else if (version == '12.3(7)JX9')
  security_warning(0);
else if (version == '12.3(7r)T')
  security_warning(0);
else if (version == '12.3(7r)T1')
  security_warning(0);
else if (version == '12.3(7r)T2')
  security_warning(0);
else if (version == '12.3(7)T')
  security_warning(0);
else if (version == '12.3(7)T1')
  security_warning(0);
else if (version == '12.3(7)T10')
  security_warning(0);
else if (version == '12.3(7)T11')
  security_warning(0);
else if (version == '12.3(7)T12')
  security_warning(0);
else if (version == '12.3(7)T2')
  security_warning(0);
else if (version == '12.3(7)T3')
  security_warning(0);
else if (version == '12.3(7)T4')
  security_warning(0);
else if (version == '12.3(7)T5')
  security_warning(0);
else if (version == '12.3(7)T6')
  security_warning(0);
else if (version == '12.3(7)T7')
  security_warning(0);
else if (version == '12.3(7)T8')
  security_warning(0);
else if (version == '12.3(7)T9')
  security_warning(0);
else if (version == '12.3(7)XI')
  security_warning(0);
else if (version == '12.3(7)XI1')
  security_warning(0);
else if (version == '12.3(7)XI10')
  security_warning(0);
else if (version == '12.3(7)XI10a')
  security_warning(0);
else if (version == '12.3(7)XI10b')
  security_warning(0);
else if (version == '12.3(7)XI1a')
  security_warning(0);
else if (version == '12.3(7)XI1b')
  security_warning(0);
else if (version == '12.3(7)XI1c')
  security_warning(0);
else if (version == '12.3(7)XI2')
  security_warning(0);
else if (version == '12.3(7)XI2a')
  security_warning(0);
else if (version == '12.3(7)XI2b')
  security_warning(0);
else if (version == '12.3(7)XI2c')
  security_warning(0);
else if (version == '12.3(7)XI3')
  security_warning(0);
else if (version == '12.3(7)XI3a')
  security_warning(0);
else if (version == '12.3(7)XI3b')
  security_warning(0);
else if (version == '12.3(7)XI3c')
  security_warning(0);
else if (version == '12.3(7)XI3d')
  security_warning(0);
else if (version == '12.3(7)XI3e')
  security_warning(0);
else if (version == '12.3(7)XI4')
  security_warning(0);
else if (version == '12.3(7)XI5')
  security_warning(0);
else if (version == '12.3(7)XI6')
  security_warning(0);
else if (version == '12.3(7)XI7')
  security_warning(0);
else if (version == '12.3(7)XI7a')
  security_warning(0);
else if (version == '12.3(7)XI7b')
  security_warning(0);
else if (version == '12.3(7)XI7c')
  security_warning(0);
else if (version == '12.3(7)XI7d')
  security_warning(0);
else if (version == '12.3(7)XI7e')
  security_warning(0);
else if (version == '12.3(7)XI7f')
  security_warning(0);
else if (version == '12.3(7)XI8')
  security_warning(0);
else if (version == '12.3(7)XI8a')
  security_warning(0);
else if (version == '12.3(7)XI8b')
  security_warning(0);
else if (version == '12.3(7)XI8c')
  security_warning(0);
else if (version == '12.3(7)XI8d')
  security_warning(0);
else if (version == '12.3(7)XI8e')
  security_warning(0);
else if (version == '12.3(7)XI8f')
  security_warning(0);
else if (version == '12.3(7)XI8g')
  security_warning(0);
else if (version == '12.3(7)XI9')
  security_warning(0);
else if (version == '12.3(7)XJ')
  security_warning(0);
else if (version == '12.3(7)XJ1')
  security_warning(0);
else if (version == '12.3(7)XJ2')
  security_warning(0);
else if (version == '12.3(7)XL')
  security_warning(0);
else if (version == '12.3(7)XM')
  security_warning(0);
else if (version == '12.3(7)XR')
  security_warning(0);
else if (version == '12.3(7)XR1')
  security_warning(0);
else if (version == '12.3(7)XR2')
  security_warning(0);
else if (version == '12.3(7)XR3')
  security_warning(0);
else if (version == '12.3(7)XR4')
  security_warning(0);
else if (version == '12.3(7)XR5')
  security_warning(0);
else if (version == '12.3(7)XR6')
  security_warning(0);
else if (version == '12.3(7)XR7')
  security_warning(0);
else if (version == '12.3(7)XS')
  security_warning(0);
else if (version == '12.3(7)XS1')
  security_warning(0);
else if (version == '12.3(7)XS2')
  security_warning(0);
else if (version == '12.3(7)YB')
  security_warning(0);
else if (version == '12.3(7)YB1')
  security_warning(0);
else if (version == '12.3(8)JA')
  security_warning(0);
else if (version == '12.3(8)JA1')
  security_warning(0);
else if (version == '12.3(8)JA2')
  security_warning(0);
else if (version == '12.3(8)JEA')
  security_warning(0);
else if (version == '12.3(8)JEA1')
  security_warning(0);
else if (version == '12.3(8)JEA2')
  security_warning(0);
else if (version == '12.3(8)JEA3')
  security_warning(0);
else if (version == '12.3(8)JEB')
  security_warning(0);
else if (version == '12.3(8)JEB1')
  security_warning(0);
else if (version == '12.3(8)JEC')
  security_warning(0);
else if (version == '12.3(8)JEE')
  security_warning(0);
else if (version == '12.3(8)JK')
  security_warning(0);
else if (version == '12.3(8)JK1')
  security_warning(0);
else if (version == '12.3(8r)T')
  security_warning(0);
else if (version == '12.3(8r)T1')
  security_warning(0);
else if (version == '12.3(8r)T10')
  security_warning(0);
else if (version == '12.3(8r)T2')
  security_warning(0);
else if (version == '12.3(8r)T3')
  security_warning(0);
else if (version == '12.3(8r)T4')
  security_warning(0);
else if (version == '12.3(8r)T5')
  security_warning(0);
else if (version == '12.3(8r)T6')
  security_warning(0);
else if (version == '12.3(8r)T7')
  security_warning(0);
else if (version == '12.3(8r)T8')
  security_warning(0);
else if (version == '12.3(8r)T9')
  security_warning(0);
else if (version == '12.3(8r)YH')
  security_warning(0);
else if (version == '12.3(8r)YH1')
  security_warning(0);
else if (version == '12.3(8r)YH10')
  security_warning(0);
else if (version == '12.3(8r)YH11')
  security_warning(0);
else if (version == '12.3(8r)YH12')
  security_warning(0);
else if (version == '12.3(8r)YH13')
  security_warning(0);
else if (version == '12.3(8r)YH2')
  security_warning(0);
else if (version == '12.3(8r)YH3')
  security_warning(0);
else if (version == '12.3(8r)YH4')
  security_warning(0);
else if (version == '12.3(8r)YH5')
  security_warning(0);
else if (version == '12.3(8r)YH6')
  security_warning(0);
else if (version == '12.3(8r)YH7')
  security_warning(0);
else if (version == '12.3(8r)YH8')
  security_warning(0);
else if (version == '12.3(8r)YH9')
  security_warning(0);
else if (version == '12.3(8)T')
  security_warning(0);
else if (version == '12.3(8)T0a')
  security_warning(0);
else if (version == '12.3(8)T1')
  security_warning(0);
else if (version == '12.3(8)T10')
  security_warning(0);
else if (version == '12.3(8)T11')
  security_warning(0);
else if (version == '12.3(8)T2')
  security_warning(0);
else if (version == '12.3(8)T3')
  security_warning(0);
else if (version == '12.3(8)T4')
  security_warning(0);
else if (version == '12.3(8)T5')
  security_warning(0);
else if (version == '12.3(8)T6')
  security_warning(0);
else if (version == '12.3(8)T7')
  security_warning(0);
else if (version == '12.3(8)T8')
  security_warning(0);
else if (version == '12.3(8)T9')
  security_warning(0);
else if (version == '12.3(8)XU')
  security_warning(0);
else if (version == '12.3(8)XU1')
  security_warning(0);
else if (version == '12.3(8)XU2')
  security_warning(0);
else if (version == '12.3(8)XU3')
  security_warning(0);
else if (version == '12.3(8)XU4')
  security_warning(0);
else if (version == '12.3(8)XU5')
  security_warning(0);
else if (version == '12.3(8)XW')
  security_warning(0);
else if (version == '12.3(8)XW1')
  security_warning(0);
else if (version == '12.3(8)XW1a')
  security_warning(0);
else if (version == '12.3(8)XW1b')
  security_warning(0);
else if (version == '12.3(8)XW2')
  security_warning(0);
else if (version == '12.3(8)XW3')
  security_warning(0);
else if (version == '12.3(8)XX')
  security_warning(0);
else if (version == '12.3(8)XX1')
  security_warning(0);
else if (version == '12.3(8)XX2')
  security_warning(0);
else if (version == '12.3(8)XX2a')
  security_warning(0);
else if (version == '12.3(8)XX2b')
  security_warning(0);
else if (version == '12.3(8)XX2c')
  security_warning(0);
else if (version == '12.3(8)XX2d')
  security_warning(0);
else if (version == '12.3(8)XX2e')
  security_warning(0);
else if (version == '12.3(8)XY')
  security_warning(0);
else if (version == '12.3(8)XY1')
  security_warning(0);
else if (version == '12.3(8)XY2')
  security_warning(0);
else if (version == '12.3(8)XY3')
  security_warning(0);
else if (version == '12.3(8)XY4')
  security_warning(0);
else if (version == '12.3(8)XY5')
  security_warning(0);
else if (version == '12.3(8)XY6')
  security_warning(0);
else if (version == '12.3(8)XY7')
  security_warning(0);
else if (version == '12.3(8)YA')
  security_warning(0);
else if (version == '12.3(8)YA1')
  security_warning(0);
else if (version == '12.3(8)YC')
  security_warning(0);
else if (version == '12.3(8)YC1')
  security_warning(0);
else if (version == '12.3(8)YC2')
  security_warning(0);
else if (version == '12.3(8)YC3')
  security_warning(0);
else if (version == '12.3(8)YD')
  security_warning(0);
else if (version == '12.3(8)YD1')
  security_warning(0);
else if (version == '12.3(8)YG')
  security_warning(0);
else if (version == '12.3(8)YG1')
  security_warning(0);
else if (version == '12.3(8)YG2')
  security_warning(0);
else if (version == '12.3(8)YG3')
  security_warning(0);
else if (version == '12.3(8)YG4')
  security_warning(0);
else if (version == '12.3(8)YG5')
  security_warning(0);
else if (version == '12.3(8)YG6')
  security_warning(0);
else if (version == '12.3(8)YH')
  security_warning(0);
else if (version == '12.3(8)YI')
  security_warning(0);
else if (version == '12.3(8)YI1')
  security_warning(0);
else if (version == '12.3(8)YI2')
  security_warning(0);
else if (version == '12.3(8)YI3')
  security_warning(0);
else if (version == '12.3(8)ZA')
  security_warning(0);
else if (version == '12.3(8)ZA1')
  security_warning(0);
else if (version == '12.3(9)')
  security_warning(0);
else if (version == '12.3(99)T')
  security_warning(0);
else if (version == '12.3(9a)')
  security_warning(0);
else if (version == '12.3(9a)BC')
  security_warning(0);
else if (version == '12.3(9a)BC1')
  security_warning(0);
else if (version == '12.3(9a)BC2')
  security_warning(0);
else if (version == '12.3(9a)BC3')
  security_warning(0);
else if (version == '12.3(9a)BC4')
  security_warning(0);
else if (version == '12.3(9a)BC5')
  security_warning(0);
else if (version == '12.3(9a)BC6')
  security_warning(0);
else if (version == '12.3(9a)BC7')
  security_warning(0);
else if (version == '12.3(9a)BC8')
  security_warning(0);
else if (version == '12.3(9a)BC9')
  security_warning(0);
else if (version == '12.3(9b)')
  security_warning(0);
else if (version == '12.3(9c)')
  security_warning(0);
else if (version == '12.3(9d)')
  security_warning(0);
else if (version == '12.3(9e)')
  security_warning(0);
else if (version == '12.3(9)M0')
  security_warning(0);
else if (version == '12.3(9)M1')
  security_warning(0);
else if (version == '12.3(9r)T')
  security_warning(0);
else if (version == '12.4(1)')
  security_warning(0);
else if (version == '12.4(1)')
  security_warning(0);
else if (version == '12.4(10)')
  security_warning(0);
else if (version == '12.4(10)')
  security_warning(0);
else if (version == '12.4(10a)')
  security_warning(0);
else if (version == '12.4(10a)')
  security_warning(0);
else if (version == '12.4(10b)')
  security_warning(0);
else if (version == '12.4(10b)')
  security_warning(0);
else if (version == '12.4(10b)JA')
  security_warning(0);
else if (version == '12.4(10b)JA')
  security_warning(0);
else if (version == '12.4(10b)JA1')
  security_warning(0);
else if (version == '12.4(10b)JA1')
  security_warning(0);
else if (version == '12.4(10b)JA2')
  security_warning(0);
else if (version == '12.4(10b)JA3')
  security_warning(0);
else if (version == '12.4(10b)JA4')
  security_warning(0);
else if (version == '12.4(10b)JDA')
  security_warning(0);
else if (version == '12.4(10b)JDA1')
  security_warning(0);
else if (version == '12.4(10b)JDA2')
  security_warning(0);
else if (version == '12.4(10b)JDA3')
  security_warning(0);
else if (version == '12.4(10b)JDC')
  security_warning(0);
else if (version == '12.4(10b)JDD')
  security_warning(0);
else if (version == '12.4(10b)JDE')
  security_warning(0);
else if (version == '12.4(10b)JX')
  security_warning(0);
else if (version == '12.4(10b)JX')
  security_warning(0);
else if (version == '12.4(10b)JY')
  security_warning(0);
else if (version == '12.4(10c)')
  security_warning(0);
else if (version == '12.4(10c)')
  security_warning(0);
else if (version == '12.4(11)MD')
  security_warning(0);
else if (version == '12.4(11)MD')
  security_warning(0);
else if (version == '12.4(11)MD1')
  security_warning(0);
else if (version == '12.4(11)MD1')
  security_warning(0);
else if (version == '12.4(11)MD10')
  security_warning(0);
else if (version == '12.4(11)MD10')
  security_warning(0);
else if (version == '12.4(11)MD2')
  security_warning(0);
else if (version == '12.4(11)MD2')
  security_warning(0);
else if (version == '12.4(11)MD3')
  security_warning(0);
else if (version == '12.4(11)MD3')
  security_warning(0);
else if (version == '12.4(11)MD4')
  security_warning(0);
else if (version == '12.4(11)MD5')
  security_warning(0);
else if (version == '12.4(11)MD6')
  security_warning(0);
else if (version == '12.4(11)MD6')
  security_warning(0);
else if (version == '12.4(11)MD7')
  security_warning(0);
else if (version == '12.4(11)MD7')
  security_warning(0);
else if (version == '12.4(11)MD8')
  security_warning(0);
else if (version == '12.4(11)MD8')
  security_warning(0);
else if (version == '12.4(11)MD9')
  security_warning(0);
else if (version == '12.4(11)MD9')
  security_warning(0);
else if (version == '12.4(11)MR')
  security_warning(0);
else if (version == '12.4(11)MR')
  security_warning(0);
else if (version == '12.4(11r)MC')
  security_warning(0);
else if (version == '12.4(11r)MC')
  security_warning(0);
else if (version == '12.4(11r)MC1')
  security_warning(0);
else if (version == '12.4(11r)MC1')
  security_warning(0);
else if (version == '12.4(11r)MC2')
  security_warning(0);
else if (version == '12.4(11r)MC2')
  security_warning(0);
else if (version == '12.4(11r)MD')
  security_warning(0);
else if (version == '12.4(11r)MD')
  security_warning(0);
else if (version == '12.4(11r)XW')
  security_warning(0);
else if (version == '12.4(11r)XW')
  security_warning(0);
else if (version == '12.4(11r)XW3')
  security_warning(0);
else if (version == '12.4(11r)XW3')
  security_warning(0);
else if (version == '12.4(11)SW')
  security_warning(0);
else if (version == '12.4(11)SW')
  security_warning(0);
else if (version == '12.4(11)SW1')
  security_warning(0);
else if (version == '12.4(11)SW1')
  security_warning(0);
else if (version == '12.4(11)SW2')
  security_warning(0);
else if (version == '12.4(11)SW2')
  security_warning(0);
else if (version == '12.4(11)SW3')
  security_warning(0);
else if (version == '12.4(11)SW3')
  security_warning(0);
else if (version == '12.4(11)T')
  security_warning(0);
else if (version == '12.4(11)T')
  security_warning(0);
else if (version == '12.4(11)T1')
  security_warning(0);
else if (version == '12.4(11)T1')
  security_warning(0);
else if (version == '12.4(11)T2')
  security_warning(0);
else if (version == '12.4(11)T2')
  security_warning(0);
else if (version == '12.4(11)T3')
  security_warning(0);
else if (version == '12.4(11)T3')
  security_warning(0);
else if (version == '12.4(11)T4')
  security_warning(0);
else if (version == '12.4(11)XJ')
  security_warning(0);
else if (version == '12.4(11)XJ')
  security_warning(0);
else if (version == '12.4(11)XJ1')
  security_warning(0);
else if (version == '12.4(11)XJ1')
  security_warning(0);
else if (version == '12.4(11)XJ2')
  security_warning(0);
else if (version == '12.4(11)XJ2')
  security_warning(0);
else if (version == '12.4(11)XJ3')
  security_warning(0);
else if (version == '12.4(11)XJ3')
  security_warning(0);
else if (version == '12.4(11)XJ4')
  security_warning(0);
else if (version == '12.4(11)XJ4')
  security_warning(0);
else if (version == '12.4(11)XJ5')
  security_warning(0);
else if (version == '12.4(11)XJ5')
  security_warning(0);
else if (version == '12.4(11)XJ6')
  security_warning(0);
else if (version == '12.4(11)XJ6')
  security_warning(0);
else if (version == '12.4(11)XV')
  security_warning(0);
else if (version == '12.4(11)XV')
  security_warning(0);
else if (version == '12.4(11)XV1')
  security_warning(0);
else if (version == '12.4(11)XV1')
  security_warning(0);
else if (version == '12.4(11)XW')
  security_warning(0);
else if (version == '12.4(11)XW')
  security_warning(0);
else if (version == '12.4(11)XW1')
  security_warning(0);
else if (version == '12.4(11)XW1')
  security_warning(0);
else if (version == '12.4(11)XW10')
  security_warning(0);
else if (version == '12.4(11)XW2')
  security_warning(0);
else if (version == '12.4(11)XW2')
  security_warning(0);
else if (version == '12.4(11)XW3')
  security_warning(0);
else if (version == '12.4(11)XW3')
  security_warning(0);
else if (version == '12.4(11)XW4')
  security_warning(0);
else if (version == '12.4(11)XW4')
  security_warning(0);
else if (version == '12.4(11)XW5')
  security_warning(0);
else if (version == '12.4(11)XW5')
  security_warning(0);
else if (version == '12.4(11)XW6')
  security_warning(0);
else if (version == '12.4(11)XW6')
  security_warning(0);
else if (version == '12.4(11)XW7')
  security_warning(0);
else if (version == '12.4(11)XW8')
  security_warning(0);
else if (version == '12.4(11)XW9')
  security_warning(0);
else if (version == '12.4(12)')
  security_warning(0);
else if (version == '12.4(12)')
  security_warning(0);
else if (version == '12.4(123e)TST')
  security_warning(0);
else if (version == '12.4(123e)TST')
  security_warning(0);
else if (version == '12.4(123g)TST')
  security_warning(0);
else if (version == '12.4(123g)TST')
  security_warning(0);
else if (version == '12.4(12a)')
  security_warning(0);
else if (version == '12.4(12a)')
  security_warning(0);
else if (version == '12.4(12b)')
  security_warning(0);
else if (version == '12.4(12b)')
  security_warning(0);
else if (version == '12.4(12c)')
  security_warning(0);
else if (version == '12.4(12c)')
  security_warning(0);
else if (version == '12.4(12)MR')
  security_warning(0);
else if (version == '12.4(12)MR')
  security_warning(0);
else if (version == '12.4(12)MR1')
  security_warning(0);
else if (version == '12.4(12)MR1')
  security_warning(0);
else if (version == '12.4(12)MR2')
  security_warning(0);
else if (version == '12.4(12)MR2')
  security_warning(0);
else if (version == '12.4(13)')
  security_warning(0);
else if (version == '12.4(13)')
  security_warning(0);
else if (version == '12.4(13a)')
  security_warning(0);
else if (version == '12.4(13a)')
  security_warning(0);
else if (version == '12.4(13b)')
  security_warning(0);
else if (version == '12.4(13b)')
  security_warning(0);
else if (version == '12.4(13c)')
  security_warning(0);
else if (version == '12.4(13c)')
  security_warning(0);
else if (version == '12.4(13d)')
  security_warning(0);
else if (version == '12.4(13d)')
  security_warning(0);
else if (version == '12.4(13d)JA')
  security_warning(0);
else if (version == '12.4(13d)JA')
  security_warning(0);
else if (version == '12.4(13e)')
  security_warning(0);
else if (version == '12.4(13e)')
  security_warning(0);
else if (version == '12.4(13f)')
  security_warning(0);
else if (version == '12.4(13r)T')
  security_warning(0);
else if (version == '12.4(13r)T')
  security_warning(0);
else if (version == '12.4(13r)T1')
  security_warning(0);
else if (version == '12.4(13r)T1')
  security_warning(0);
else if (version == '12.4(13r)T10')
  security_warning(0);
else if (version == '12.4(13r)T10')
  security_warning(0);
else if (version == '12.4(13r)T11')
  security_warning(0);
else if (version == '12.4(13r)T11')
  security_warning(0);
else if (version == '12.4(13r)T12')
  security_warning(0);
else if (version == '12.4(13r)T12')
  security_warning(0);
else if (version == '12.4(13r)T13')
  security_warning(0);
else if (version == '12.4(13r)T13')
  security_warning(0);
else if (version == '12.4(13r)T14')
  security_warning(0);
else if (version == '12.4(13r)T14')
  security_warning(0);
else if (version == '12.4(13r)T15')
  security_warning(0);
else if (version == '12.4(13r)T15')
  security_warning(0);
else if (version == '12.4(13r)T16')
  security_warning(0);
else if (version == '12.4(13r)T16')
  security_warning(0);
else if (version == '12.4(13r)T2')
  security_warning(0);
else if (version == '12.4(13r)T2')
  security_warning(0);
else if (version == '12.4(13r)T3')
  security_warning(0);
else if (version == '12.4(13r)T3')
  security_warning(0);
else if (version == '12.4(13r)T4')
  security_warning(0);
else if (version == '12.4(13r)T4')
  security_warning(0);
else if (version == '12.4(13r)T5')
  security_warning(0);
else if (version == '12.4(13r)T5')
  security_warning(0);
else if (version == '12.4(13r)T6')
  security_warning(0);
else if (version == '12.4(13r)T6')
  security_warning(0);
else if (version == '12.4(13r)T7')
  security_warning(0);
else if (version == '12.4(13r)T7')
  security_warning(0);
else if (version == '12.4(13r)T8')
  security_warning(0);
else if (version == '12.4(13r)T8')
  security_warning(0);
else if (version == '12.4(13r)T9')
  security_warning(0);
else if (version == '12.4(13r)T9')
  security_warning(0);
else if (version == '12.4(14r)')
  security_warning(0);
else if (version == '12.4(14r)')
  security_warning(0);
else if (version == '12.4(14r)T')
  security_warning(0);
else if (version == '12.4(14r)T')
  security_warning(0);
else if (version == '12.4(14)XK')
  security_warning(0);
else if (version == '12.4(14)XK')
  security_warning(0);
else if (version == '12.4(15)SW')
  security_warning(0);
else if (version == '12.4(15)SW')
  security_warning(0);
else if (version == '12.4(15)SW1')
  security_warning(0);
else if (version == '12.4(15)SW2')
  security_warning(0);
else if (version == '12.4(15)SW2')
  security_warning(0);
else if (version == '12.4(15)SW3')
  security_warning(0);
else if (version == '12.4(15)SW3')
  security_warning(0);
else if (version == '12.4(15)SW4')
  security_warning(0);
else if (version == '12.4(15)SW4')
  security_warning(0);
else if (version == '12.4(15)SW5')
  security_warning(0);
else if (version == '12.4(15)SW5')
  security_warning(0);
else if (version == '12.4(15)SW6')
  security_warning(0);
else if (version == '12.4(15)SW6')
  security_warning(0);
else if (version == '12.4(15)SW7')
  security_warning(0);
else if (version == '12.4(15)SW7')
  security_warning(0);
else if (version == '12.4(15)SW8')
  security_warning(0);
else if (version == '12.4(15)SW8')
  security_warning(0);
else if (version == '12.4(15)SW8a')
  security_warning(0);
else if (version == '12.4(15)SW8a')
  security_warning(0);
else if (version == '12.4(15)T')
  security_warning(0);
else if (version == '12.4(15)T')
  security_warning(0);
else if (version == '12.4(15)T1')
  security_warning(0);
else if (version == '12.4(15)T1')
  security_warning(0);
else if (version == '12.4(15)XF')
  security_warning(0);
else if (version == '12.4(15)XF')
  security_warning(0);
else if (version == '12.4(15)XL')
  security_warning(0);
else if (version == '12.4(15)XL')
  security_warning(0);
else if (version == '12.4(15)XL1')
  security_warning(0);
else if (version == '12.4(15)XL1')
  security_warning(0);
else if (version == '12.4(15)XL2')
  security_warning(0);
else if (version == '12.4(15)XL2')
  security_warning(0);
else if (version == '12.4(15)XL3')
  security_warning(0);
else if (version == '12.4(15)XL3')
  security_warning(0);
else if (version == '12.4(15)XL4')
  security_warning(0);
else if (version == '12.4(15)XL4')
  security_warning(0);
else if (version == '12.4(15)XL5')
  security_warning(0);
else if (version == '12.4(15)XL5')
  security_warning(0);
else if (version == '12.4(15)XY')
  security_warning(0);
else if (version == '12.4(15)XY1')
  security_warning(0);
else if (version == '12.4(15)XY2')
  security_warning(0);
else if (version == '12.4(15)XY3')
  security_warning(0);
else if (version == '12.4(15)XY4')
  security_warning(0);
else if (version == '12.4(15)XY5')
  security_warning(0);
else if (version == '12.4(16)')
  security_warning(0);
else if (version == '12.4(16)')
  security_warning(0);
else if (version == '12.4(16a)')
  security_warning(0);
else if (version == '12.4(16a)')
  security_warning(0);
else if (version == '12.4(16b)')
  security_warning(0);
else if (version == '12.4(16b)')
  security_warning(0);
else if (version == '12.4(16b)JA')
  security_warning(0);
else if (version == '12.4(16b)JA1')
  security_warning(0);
else if (version == '12.4(16)MR')
  security_warning(0);
else if (version == '12.4(16)MR')
  security_warning(0);
else if (version == '12.4(16)MR1')
  security_warning(0);
else if (version == '12.4(16)MR1')
  security_warning(0);
else if (version == '12.4(16)MR2')
  security_warning(0);
else if (version == '12.4(16)TRY1')
  security_warning(0);
else if (version == '12.4(16)TRY1')
  security_warning(0);
else if (version == '12.4(17)')
  security_warning(0);
else if (version == '12.4(17)')
  security_warning(0);
else if (version == '12.4(17a)')
  security_warning(0);
else if (version == '12.4(17a)')
  security_warning(0);
else if (version == '12.4(17b)')
  security_warning(0);
else if (version == '12.4(1a)')
  security_warning(0);
else if (version == '12.4(1a)')
  security_warning(0);
else if (version == '12.4(1b)')
  security_warning(0);
else if (version == '12.4(1b)')
  security_warning(0);
else if (version == '12.4(1c)')
  security_warning(0);
else if (version == '12.4(1c)')
  security_warning(0);
else if (version == '12.4(1r)')
  security_warning(0);
else if (version == '12.4(1r)')
  security_warning(0);
else if (version == '12.4(24r)SB')
  security_warning(0);
else if (version == '12.4(24r)SB')
  security_warning(0);
else if (version == '12.4(2)MR')
  security_warning(0);
else if (version == '12.4(2)MR')
  security_warning(0);
else if (version == '12.4(2)MR1')
  security_warning(0);
else if (version == '12.4(2)MR1')
  security_warning(0);
else if (version == '12.4(2r)XM1')
  security_warning(0);
else if (version == '12.4(2r)XM1')
  security_warning(0);
else if (version == '12.4(2)T')
  security_warning(0);
else if (version == '12.4(2)T')
  security_warning(0);
else if (version == '12.4(2)T1')
  security_warning(0);
else if (version == '12.4(2)T2')
  security_warning(0);
else if (version == '12.4(2)T2')
  security_warning(0);
else if (version == '12.4(2)T3')
  security_warning(0);
else if (version == '12.4(2)T3')
  security_warning(0);
else if (version == '12.4(2)T4')
  security_warning(0);
else if (version == '12.4(2)T4')
  security_warning(0);
else if (version == '12.4(2)T5')
  security_warning(0);
else if (version == '12.4(2)T5')
  security_warning(0);
else if (version == '12.4(2)T6')
  security_warning(0);
else if (version == '12.4(2)T6')
  security_warning(0);
else if (version == '12.4(2)XA')
  security_warning(0);
else if (version == '12.4(2)XA')
  security_warning(0);
else if (version == '12.4(2)XA1')
  security_warning(0);
else if (version == '12.4(2)XA1')
  security_warning(0);
else if (version == '12.4(2)XA2')
  security_warning(0);
else if (version == '12.4(2)XA2')
  security_warning(0);
else if (version == '12.4(2)XB')
  security_warning(0);
else if (version == '12.4(2)XB')
  security_warning(0);
else if (version == '12.4(2)XB052306')
  security_warning(0);
else if (version == '12.4(2)XB052306')
  security_warning(0);
else if (version == '12.4(2)XB1')
  security_warning(0);
else if (version == '12.4(2)XB1')
  security_warning(0);
else if (version == '12.4(2)XB10')
  security_warning(0);
else if (version == '12.4(2)XB11')
  security_warning(0);
else if (version == '12.4(2)XB12')
  security_warning(0);
else if (version == '12.4(2)XB2')
  security_warning(0);
else if (version == '12.4(2)XB2')
  security_warning(0);
else if (version == '12.4(2)XB3')
  security_warning(0);
else if (version == '12.4(2)XB3')
  security_warning(0);
else if (version == '12.4(2)XB4')
  security_warning(0);
else if (version == '12.4(2)XB4')
  security_warning(0);
else if (version == '12.4(2)XB5')
  security_warning(0);
else if (version == '12.4(2)XB5')
  security_warning(0);
else if (version == '12.4(2)XB6')
  security_warning(0);
else if (version == '12.4(2)XB6')
  security_warning(0);
else if (version == '12.4(2)XB7')
  security_warning(0);
else if (version == '12.4(2)XB7')
  security_warning(0);
else if (version == '12.4(2)XB8')
  security_warning(0);
else if (version == '12.4(2)XB8')
  security_warning(0);
else if (version == '12.4(2)XB9')
  security_warning(0);
else if (version == '12.4(2)XB9')
  security_warning(0);
else if (version == '12.4(3)')
  security_warning(0);
else if (version == '12.4(3)')
  security_warning(0);
else if (version == '12.4(3a)')
  security_warning(0);
else if (version == '12.4(3a)')
  security_warning(0);
else if (version == '12.4(3b)')
  security_warning(0);
else if (version == '12.4(3b)')
  security_warning(0);
else if (version == '12.4(3c)')
  security_warning(0);
else if (version == '12.4(3c)')
  security_warning(0);
else if (version == '12.4(3d)')
  security_warning(0);
else if (version == '12.4(3d)')
  security_warning(0);
else if (version == '12.4(3e)')
  security_warning(0);
else if (version == '12.4(3e)')
  security_warning(0);
else if (version == '12.4(3f)')
  security_warning(0);
else if (version == '12.4(3f)')
  security_warning(0);
else if (version == '12.4(3g)')
  security_warning(0);
else if (version == '12.4(3g)')
  security_warning(0);
else if (version == '12.4(3g)JA')
  security_warning(0);
else if (version == '12.4(3g)JA')
  security_warning(0);
else if (version == '12.4(3g)JA1')
  security_warning(0);
else if (version == '12.4(3g)JA1')
  security_warning(0);
else if (version == '12.4(3g)JA2')
  security_warning(0);
else if (version == '12.4(3g)JA2')
  security_warning(0);
else if (version == '12.4(3g)JMA')
  security_warning(0);
else if (version == '12.4(3g)JMA')
  security_warning(0);
else if (version == '12.4(3g)JMA1')
  security_warning(0);
else if (version == '12.4(3g)JMA1')
  security_warning(0);
else if (version == '12.4(3g)JMB')
  security_warning(0);
else if (version == '12.4(3g)JMB')
  security_warning(0);
else if (version == '12.4(3g)JMC')
  security_warning(0);
else if (version == '12.4(3g)JMC')
  security_warning(0);
else if (version == '12.4(3g)JMC1')
  security_warning(0);
else if (version == '12.4(3g)JMC2')
  security_warning(0);
else if (version == '12.4(3g)JX')
  security_warning(0);
else if (version == '12.4(3g)JX')
  security_warning(0);
else if (version == '12.4(3g)JX1')
  security_warning(0);
else if (version == '12.4(3g)JX1')
  security_warning(0);
else if (version == '12.4(3g)JX2')
  security_warning(0);
else if (version == '12.4(3g)JX2')
  security_warning(0);
else if (version == '12.4(3h)')
  security_warning(0);
else if (version == '12.4(3h)')
  security_warning(0);
else if (version == '12.4(3h)BAK')
  security_warning(0);
else if (version == '12.4(3h)BAK')
  security_warning(0);
else if (version == '12.4(3i)')
  security_warning(0);
else if (version == '12.4(3i)')
  security_warning(0);
else if (version == '12.4(3j)')
  security_warning(0);
else if (version == '12.4(3j)')
  security_warning(0);
else if (version == '12.4(3)JK')
  security_warning(0);
else if (version == '12.4(3)JK')
  security_warning(0);
else if (version == '12.4(3)JK1')
  security_warning(0);
else if (version == '12.4(3)JK2')
  security_warning(0);
else if (version == '12.4(3)JK3')
  security_warning(0);
else if (version == '12.4(3)JL')
  security_warning(0);
else if (version == '12.4(3)JL')
  security_warning(0);
else if (version == '12.4(3)JL1')
  security_warning(0);
else if (version == '12.4(3)JL1')
  security_warning(0);
else if (version == '12.4(3)JL2')
  security_warning(0);
else if (version == '12.4(3)JL2')
  security_warning(0);
else if (version == '12.4(4)MR')
  security_warning(0);
else if (version == '12.4(4)MR')
  security_warning(0);
else if (version == '12.4(4)MR1')
  security_warning(0);
else if (version == '12.4(4)MR1')
  security_warning(0);
else if (version == '12.4(4r)XC')
  security_warning(0);
else if (version == '12.4(4r)XC')
  security_warning(0);
else if (version == '12.4(4r)XD')
  security_warning(0);
else if (version == '12.4(4r)XD')
  security_warning(0);
else if (version == '12.4(4r)XD1')
  security_warning(0);
else if (version == '12.4(4r)XD1')
  security_warning(0);
else if (version == '12.4(4r)XD2')
  security_warning(0);
else if (version == '12.4(4r)XD2')
  security_warning(0);
else if (version == '12.4(4r)XD3')
  security_warning(0);
else if (version == '12.4(4r)XD3')
  security_warning(0);
else if (version == '12.4(4r)XD4')
  security_warning(0);
else if (version == '12.4(4r)XD4')
  security_warning(0);
else if (version == '12.4(4r)XD5')
  security_warning(0);
else if (version == '12.4(4r)XD5')
  security_warning(0);
else if (version == '12.4(4)T')
  security_warning(0);
else if (version == '12.4(4)T')
  security_warning(0);
else if (version == '12.4(4)T1')
  security_warning(0);
else if (version == '12.4(4)T1')
  security_warning(0);
else if (version == '12.4(4)T2')
  security_warning(0);
else if (version == '12.4(4)T2')
  security_warning(0);
else if (version == '12.4(4)T3')
  security_warning(0);
else if (version == '12.4(4)T3')
  security_warning(0);
else if (version == '12.4(4)T4')
  security_warning(0);
else if (version == '12.4(4)T4')
  security_warning(0);
else if (version == '12.4(4)T5')
  security_warning(0);
else if (version == '12.4(4)T5')
  security_warning(0);
else if (version == '12.4(4)T6')
  security_warning(0);
else if (version == '12.4(4)T6')
  security_warning(0);
else if (version == '12.4(4)T7')
  security_warning(0);
else if (version == '12.4(4)T7')
  security_warning(0);
else if (version == '12.4(4)T8')
  security_warning(0);
else if (version == '12.4(4)T8')
  security_warning(0);
else if (version == '12.4(4)XC')
  security_warning(0);
else if (version == '12.4(4)XC')
  security_warning(0);
else if (version == '12.4(4)XC1')
  security_warning(0);
else if (version == '12.4(4)XC1')
  security_warning(0);
else if (version == '12.4(4)XC2')
  security_warning(0);
else if (version == '12.4(4)XC2')
  security_warning(0);
else if (version == '12.4(4)XC3')
  security_warning(0);
else if (version == '12.4(4)XC3')
  security_warning(0);
else if (version == '12.4(4)XC4')
  security_warning(0);
else if (version == '12.4(4)XC4')
  security_warning(0);
else if (version == '12.4(4)XC5')
  security_warning(0);
else if (version == '12.4(4)XC5')
  security_warning(0);
else if (version == '12.4(4)XC6')
  security_warning(0);
else if (version == '12.4(4)XC6')
  security_warning(0);
else if (version == '12.4(4)XC7')
  security_warning(0);
else if (version == '12.4(4)XC7')
  security_warning(0);
else if (version == '12.4(4)XD')
  security_warning(0);
else if (version == '12.4(4)XD')
  security_warning(0);
else if (version == '12.4(4)XD0')
  security_warning(0);
else if (version == '12.4(4)XD0')
  security_warning(0);
else if (version == '12.4(4)XD1')
  security_warning(0);
else if (version == '12.4(4)XD1')
  security_warning(0);
else if (version == '12.4(4)XD10')
  security_warning(0);
else if (version == '12.4(4)XD11')
  security_warning(0);
else if (version == '12.4(4)XD12')
  security_warning(0);
else if (version == '12.4(4)XD2')
  security_warning(0);
else if (version == '12.4(4)XD2')
  security_warning(0);
else if (version == '12.4(4)XD3')
  security_warning(0);
else if (version == '12.4(4)XD3')
  security_warning(0);
else if (version == '12.4(4)XD4')
  security_warning(0);
else if (version == '12.4(4)XD4')
  security_warning(0);
else if (version == '12.4(4)XD5')
  security_warning(0);
else if (version == '12.4(4)XD5')
  security_warning(0);
else if (version == '12.4(4)XD6')
  security_warning(0);
else if (version == '12.4(4)XD6')
  security_warning(0);
else if (version == '12.4(4)XD7')
  security_warning(0);
else if (version == '12.4(4)XD7')
  security_warning(0);
else if (version == '12.4(4)XD7a')
  security_warning(0);
else if (version == '12.4(4)XD7a')
  security_warning(0);
else if (version == '12.4(4)XD7b')
  security_warning(0);
else if (version == '12.4(4)XD7b')
  security_warning(0);
else if (version == '12.4(4)XD7c')
  security_warning(0);
else if (version == '12.4(4)XD7c')
  security_warning(0);
else if (version == '12.4(4)XD8')
  security_warning(0);
else if (version == '12.4(4)XD8')
  security_warning(0);
else if (version == '12.4(4)XD8a')
  security_warning(0);
else if (version == '12.4(4)XD8a')
  security_warning(0);
else if (version == '12.4(4)XD9')
  security_warning(0);
else if (version == '12.4(4)XD9')
  security_warning(0);
else if (version == '12.4(5)')
  security_warning(0);
else if (version == '12.4(5)')
  security_warning(0);
else if (version == '12.4(555)TEST')
  security_warning(0);
else if (version == '12.4(555)TEST')
  security_warning(0);
else if (version == '12.4(567b)TST')
  security_warning(0);
else if (version == '12.4(567b)TST')
  security_warning(0);
else if (version == '12.4(57)ARF')
  security_warning(0);
else if (version == '12.4(57)ARF')
  security_warning(0);
else if (version == '12.4(57)ARF2')
  security_warning(0);
else if (version == '12.4(57)ARF2')
  security_warning(0);
else if (version == '12.4(57)COMP')
  security_warning(0);
else if (version == '12.4(57)COMP')
  security_warning(0);
else if (version == '12.4(5a)')
  security_warning(0);
else if (version == '12.4(5a)')
  security_warning(0);
else if (version == '12.4(5a)M0')
  security_warning(0);
else if (version == '12.4(5a)M0')
  security_warning(0);
else if (version == '12.4(5b)')
  security_warning(0);
else if (version == '12.4(5b)')
  security_warning(0);
else if (version == '12.4(5c)')
  security_warning(0);
else if (version == '12.4(5c)')
  security_warning(0);
else if (version == '12.4(6)MR')
  security_warning(0);
else if (version == '12.4(6)MR')
  security_warning(0);
else if (version == '12.4(6)MR1')
  security_warning(0);
else if (version == '12.4(6)MR1')
  security_warning(0);
else if (version == '12.4(6r)XE')
  security_warning(0);
else if (version == '12.4(6r)XE')
  security_warning(0);
else if (version == '12.4(6)T')
  security_warning(0);
else if (version == '12.4(6)T')
  security_warning(0);
else if (version == '12.4(6)T1')
  security_warning(0);
else if (version == '12.4(6)T1')
  security_warning(0);
else if (version == '12.4(6)T10')
  security_warning(0);
else if (version == '12.4(6)T10')
  security_warning(0);
else if (version == '12.4(6)T11')
  security_warning(0);
else if (version == '12.4(6)T12')
  security_warning(0);
else if (version == '12.4(6)T2')
  security_warning(0);
else if (version == '12.4(6)T2')
  security_warning(0);
else if (version == '12.4(6)T3')
  security_warning(0);
else if (version == '12.4(6)T3')
  security_warning(0);
else if (version == '12.4(6)T4')
  security_warning(0);
else if (version == '12.4(6)T4')
  security_warning(0);
else if (version == '12.4(6)T5')
  security_warning(0);
else if (version == '12.4(6)T5')
  security_warning(0);
else if (version == '12.4(6)T5a')
  security_warning(0);
else if (version == '12.4(6)T5a')
  security_warning(0);
else if (version == '12.4(6)T5b')
  security_warning(0);
else if (version == '12.4(6)T5c')
  security_warning(0);
else if (version == '12.4(6)T5d')
  security_warning(0);
else if (version == '12.4(6)T5e')
  security_warning(0);
else if (version == '12.4(6)T5f')
  security_warning(0);
else if (version == '12.4(6)T6')
  security_warning(0);
else if (version == '12.4(6)T6')
  security_warning(0);
else if (version == '12.4(6)T7')
  security_warning(0);
else if (version == '12.4(6)T7')
  security_warning(0);
else if (version == '12.4(6)T8')
  security_warning(0);
else if (version == '12.4(6)T8')
  security_warning(0);
else if (version == '12.4(6)T9')
  security_warning(0);
else if (version == '12.4(6)T9')
  security_warning(0);
else if (version == '12.4(6t)EB2')
  security_warning(0);
else if (version == '12.4(6t)EB2')
  security_warning(0);
else if (version == '12.4(6t)EB3')
  security_warning(0);
else if (version == '12.4(6t)EB3')
  security_warning(0);
else if (version == '12.4(6t)EB4')
  security_warning(0);
else if (version == '12.4(6t)EB4')
  security_warning(0);
else if (version == '12.4(6t)EB5')
  security_warning(0);
else if (version == '12.4(6t)EB5')
  security_warning(0);
else if (version == '12.4(6)XE')
  security_warning(0);
else if (version == '12.4(6)XE')
  security_warning(0);
else if (version == '12.4(6)XE1')
  security_warning(0);
else if (version == '12.4(6)XE1')
  security_warning(0);
else if (version == '12.4(6)XE2')
  security_warning(0);
else if (version == '12.4(6)XE2')
  security_warning(0);
else if (version == '12.4(6)XE3')
  security_warning(0);
else if (version == '12.4(6)XE3')
  security_warning(0);
else if (version == '12.4(6)XE4')
  security_warning(0);
else if (version == '12.4(6)XP')
  security_warning(0);
else if (version == '12.4(6)XP')
  security_warning(0);
else if (version == '12.4(6)XT')
  security_warning(0);
else if (version == '12.4(6)XT')
  security_warning(0);
else if (version == '12.4(6)XT1')
  security_warning(0);
else if (version == '12.4(6)XT1')
  security_warning(0);
else if (version == '12.4(6)XT2')
  security_warning(0);
else if (version == '12.4(6)XT2')
  security_warning(0);
else if (version == '12.4(7)')
  security_warning(0);
else if (version == '12.4(7)')
  security_warning(0);
else if (version == '12.4(77)T')
  security_warning(0);
else if (version == '12.4(77)T')
  security_warning(0);
else if (version == '12.4(789a)TST')
  security_warning(0);
else if (version == '12.4(789a)TST')
  security_warning(0);
else if (version == '12.4(7a)')
  security_warning(0);
else if (version == '12.4(7a)')
  security_warning(0);
else if (version == '12.4(7b)')
  security_warning(0);
else if (version == '12.4(7b)')
  security_warning(0);
else if (version == '12.4(7c)')
  security_warning(0);
else if (version == '12.4(7c)')
  security_warning(0);
else if (version == '12.4(7d)')
  security_warning(0);
else if (version == '12.4(7d)')
  security_warning(0);
else if (version == '12.4(7e)')
  security_warning(0);
else if (version == '12.4(7e)')
  security_warning(0);
else if (version == '12.4(7f)')
  security_warning(0);
else if (version == '12.4(7f)')
  security_warning(0);
else if (version == '12.4(7g)')
  security_warning(0);
else if (version == '12.4(7g)')
  security_warning(0);
else if (version == '12.4(7h)')
  security_warning(0);
else if (version == '12.4(7h)')
  security_warning(0);
else if (version == '12.4(8)')
  security_warning(0);
else if (version == '12.4(8)')
  security_warning(0);
else if (version == '12.4(80)TEST')
  security_warning(0);
else if (version == '12.4(80)TEST')
  security_warning(0);
else if (version == '12.4(8a)')
  security_warning(0);
else if (version == '12.4(8a)')
  security_warning(0);
else if (version == '12.4(8b)')
  security_warning(0);
else if (version == '12.4(8b)')
  security_warning(0);
else if (version == '12.4(8c)')
  security_warning(0);
else if (version == '12.4(8c)')
  security_warning(0);
else if (version == '12.4(8d)')
  security_warning(0);
else if (version == '12.4(8d)')
  security_warning(0);
else if (version == '12.4(99)')
  security_warning(0);
else if (version == '12.4(99)')
  security_warning(0);
else if (version == '12.4(999)JA')
  security_warning(0);
else if (version == '12.4(99)TEST4')
  security_warning(0);
else if (version == '12.4(99)TEST4')
  security_warning(0);
else if (version == '12.4(9)MR')
  security_warning(0);
else if (version == '12.4(9)MR')
  security_warning(0);
else if (version == '12.4(9)T')
  security_warning(0);
else if (version == '12.4(9)T')
  security_warning(0);
else if (version == '12.4(9)T0a')
  security_warning(0);
else if (version == '12.4(9)T0a')
  security_warning(0);
else if (version == '12.4(9)T1')
  security_warning(0);
else if (version == '12.4(9)T1')
  security_warning(0);
else if (version == '12.4(9)T2')
  security_warning(0);
else if (version == '12.4(9)T2')
  security_warning(0);
else if (version == '12.4(9)T3')
  security_warning(0);
else if (version == '12.4(9)T3')
  security_warning(0);
else if (version == '12.4(9)T4')
  security_warning(0);
else if (version == '12.4(9)T4')
  security_warning(0);
else if (version == '12.4(9)T5')
  security_warning(0);
else if (version == '12.4(9)T5')
  security_warning(0);
else if (version == '12.4(9)T6')
  security_warning(0);
else if (version == '12.4(9)T7')
  security_warning(0);
else if (version == '12.4(9)XG')
  security_warning(0);
else if (version == '12.4(9)XG')
  security_warning(0);
else if (version == '12.4(9)XG1')
  security_warning(0);
else if (version == '12.4(9)XG1')
  security_warning(0);
else if (version == '12.4(9)XG2')
  security_warning(0);
else if (version == '12.4(9)XG2')
  security_warning(0);
else if (version == '12.4(9)XG3')
  security_warning(0);
else if (version == '12.4(9)XG4')
  security_warning(0);
else if (version == '12.4(9)XG5')
  security_warning(0);
else if (version == '12.5(1)')
  security_warning(0);
else if (version == '12.5(1)')
  security_warning(0);
else if (version == '12.5(88888883)')
  security_warning(0);
else if (version == '12.5(88888883)')
  security_warning(0);
else if (version == '12.5(888888882)')
  security_warning(0);
else if (version == '12.5(888888882)')
  security_warning(0);
else if (version == '12.9(9)S0225')
  security_warning(0);
else if (version == '12.9(9)S0225')
  security_warning(0);
else if (version == '15.0(1)')
  security_warning(0);
else if (version == '15.0(1)')
  security_warning(0);
else if (version == '15.0(1)M1')
  security_warning(0);
else if (version == '15.0(1)M1')
  security_warning(0);
else if (version == '15.0(1)M2')
  security_warning(0);
else if (version == '15.0(1)M2')
  security_warning(0);
else if (version == '15.0(1)M3')
  security_warning(0);
else if (version == '15.0(1)M3')
  security_warning(0);
else if (version == '15.0(1)M4')
  security_warning(0);
else if (version == '15.0(1)M4')
  security_warning(0);
else if (version == '15.0(1)M5')
  security_warning(0);
else if (version == '15.0(1)M5')
  security_warning(0);
else if (version == '15.0(1)M6')
  security_warning(0);
else if (version == '15.0(1)M6')
  security_warning(0);
else if (version == '15.0(1)M6a')
  security_warning(0);
else if (version == '15.0(1)M6a')
  security_warning(0);
else if (version == '15.0(1)M7')
  security_warning(0);
else if (version == '15.0(1)M7')
  security_warning(0);
else if (version == '15.0(98)CCAI')
  security_warning(0);
else if (version == '15.0(98)CCAI')
  security_warning(0);
else if (version == '15.0(9988)M1')
  security_warning(0);
else if (version == '15.0(9988)M1')
  security_warning(0);
else if (version == '15.0(9999)M1')
  security_warning(0);
else if (version == '15.0(9999)M1')
  security_warning(0);
else if (version == '15.1(4)')
  security_warning(0);
else if (version == '15.1(4)')
  security_warning(0);
else if (version == '15.1(4)M0a')
  security_warning(0);
else if (version == '15.1(4)M0a')
  security_warning(0);
else if (version == '15.1(4)M0b')
  security_warning(0);
else if (version == '15.1(4)M0b')
  security_warning(0);
else if (version == '15.1(4)M1')
  security_warning(0);
else if (version == '15.1(4)M1')
  security_warning(0);
else if (version == '15.1(4)M2')
  security_warning(0);
else if (version == '15.1(4)M2')
  security_warning(0);
else if (version == '15.1(4)M3')
  security_warning(0);
else if (version == '15.1(4)M3')
  security_warning(0);
else if (version == '15.1(4)M3a')
  security_warning(0);
else if (version == '15.1(4)M3a')
  security_warning(0);
else if (version == '15.1(4r)M2')
  security_warning(0);
else if (version == '15.1(4r)M2')
  security_warning(0);
else if (version == '15.1(4)XB4')
  security_warning(0);
else if (version == '15.1(4)XB4')
  security_warning(0);
else if (version == '15.1(4)XB5')
  security_warning(0);
else if (version == '15.1(4)XB5')
  security_warning(0);
else if (version == '15.1(4)XB5a')
  security_warning(0);
else if (version == '15.1(4)XB5a')
  security_warning(0);
else if (version == '15.1(4)XB6')
  security_warning(0);
else if (version == '15.1(4)XB6')
  security_warning(0);
else if (version == '15.1(4)XB7')
  security_warning(0);
else if (version == '15.1(4)XB7')
  security_warning(0);
else
  audit(AUDIT_HOST_NOT, 'affected');
