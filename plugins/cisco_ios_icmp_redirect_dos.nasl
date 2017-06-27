#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17794);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2002-2315");
  script_bugtraq_id(4786);
  script_osvdb_id(60078);
  script_xref(name:"CISCO-BUG-ID", value:"CSCdx32056");

  script_name(english:"Cisco IOS ICMP Redirect Denial of Service");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"It is possible to cause a denial of service by flooding the remote
device with ICMP requests, which will cause the redirect cache to
grow.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/May/198");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch which can be obtained from the Cisco Bug 
tracker.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("cisco_func.inc");
include("audit.inc");

version = get_kb_item_or_exit('Host/Cisco/IOS/Version');

if (version == '12.1(0)PCHK1')
  security_hole(0);
else if (version == '12.1(0)PCHK10')
  security_hole(0);
else if (version == '12.1(0)PCHK11')
  security_hole(0);
else if (version == '12.1(0)PCHK12')
  security_hole(0);
else if (version == '12.1(0)PCHK13')
  security_hole(0);
else if (version == '12.1(0)PCHK14')
  security_hole(0);
else if (version == '12.1(0)PCHK15')
  security_hole(0);
else if (version == '12.1(0)PCHK16')
  security_hole(0);
else if (version == '12.1(0)PCHK17')
  security_hole(0);
else if (version == '12.1(0)PCHK18')
  security_hole(0);
else if (version == '12.1(0)PCHK19')
  security_hole(0);
else if (version == '12.1(0)PCHK2')
  security_hole(0);
else if (version == '12.1(0)PCHK20')
  security_hole(0);
else if (version == '12.1(0)PCHK21')
  security_hole(0);
else if (version == '12.1(0)PCHK22')
  security_hole(0);
else if (version == '12.1(0)PCHK23')
  security_hole(0);
else if (version == '12.1(0)PCHK24')
  security_hole(0);
else if (version == '12.1(0)PCHK3')
  security_hole(0);
else if (version == '12.1(0)PCHK4')
  security_hole(0);
else if (version == '12.1(0)PCHK5')
  security_hole(0);
else if (version == '12.1(0)PCHK6')
  security_hole(0);
else if (version == '12.1(0)PCHK7')
  security_hole(0);
else if (version == '12.1(0)PCHK8')
  security_hole(0);
else if (version == '12.1(0)PCHK9')
  security_hole(0);
else if (version == '12.1(0)PCHK92')
  security_hole(0);
else if (version == '12.1(1)')
  security_hole(0);
else if (version == '12.1(10)')
  security_hole(0);
else if (version == '12.1(10a)')
  security_hole(0);
else if (version == '12.1(10)AA')
  security_hole(0);
else if (version == '12.1(10)E7')
  security_hole(0);
else if (version == '12.1(10)E8')
  security_hole(0);
else if (version == '12.1(10)EC')
  security_hole(0);
else if (version == '12.1(10)EC1')
  security_hole(0);
else if (version == '12.1(10)EV')
  security_hole(0);
else if (version == '12.1(10)EV1')
  security_hole(0);
else if (version == '12.1(10)EV1a')
  security_hole(0);
else if (version == '12.1(10)EV1b')
  security_hole(0);
else if (version == '12.1(10)EV2')
  security_hole(0);
else if (version == '12.1(10)EV3')
  security_hole(0);
else if (version == '12.1(10)EV4')
  security_hole(0);
else if (version == '12.1(10)EX')
  security_hole(0);
else if (version == '12.1(10)EX1')
  security_hole(0);
else if (version == '12.1(10)EX2')
  security_hole(0);
else if (version == '12.1(10)EY')
  security_hole(0);
else if (version == '12.1(10r)EV')
  security_hole(0);
else if (version == '12.1(10r)EV1')
  security_hole(0);
else if (version == '12.1(11)')
  security_hole(0);
else if (version == '12.1(11a)')
  security_hole(0);
else if (version == '12.1(11a)EW')
  security_hole(0);
else if (version == '12.1(11b)')
  security_hole(0);
else if (version == '12.1(11b)E')
  security_hole(0);
else if (version == '12.1(11b)E0a')
  security_hole(0);
else if (version == '12.1(11b)E1')
  security_hole(0);
else if (version == '12.1(11b)E10')
  security_hole(0);
else if (version == '12.1(11b)E11')
  security_hole(0);
else if (version == '12.1(11b)E12')
  security_hole(0);
else if (version == '12.1(11b)E13')
  security_hole(0);
else if (version == '12.1(11b)E14')
  security_hole(0);
else if (version == '12.1(11b)E2')
  security_hole(0);
else if (version == '12.1(11b)E3')
  security_hole(0);
else if (version == '12.1(11b)E4')
  security_hole(0);
else if (version == '12.1(11b)E5')
  security_hole(0);
else if (version == '12.1(11b)E6')
  security_hole(0);
else if (version == '12.1(11b)E7')
  security_hole(0);
else if (version == '12.1(11b)E8')
  security_hole(0);
else if (version == '12.1(11b)E9')
  security_hole(0);
else if (version == '12.1(11b)EC')
  security_hole(0);
else if (version == '12.1(11b)EC1')
  security_hole(0);
else if (version == '12.1(11b)EW')
  security_hole(0);
else if (version == '12.1(11b)EW1')
  security_hole(0);
else if (version == '12.1(11b)EX')
  security_hole(0);
else if (version == '12.1(11b)EX1')
  security_hole(0);
else if (version == '12.1(11)E')
  security_hole(0);
else if (version == '12.1(11)EA1')
  security_hole(0);
else if (version == '12.1(11)EA1a')
  security_hole(0);
else if (version == '12.1(11e)CSFB')
  security_hole(0);
else if (version == '12.1(11)EX')
  security_hole(0);
else if (version == '12.1(11r)E')
  security_hole(0);
else if (version == '12.1(11r)E1')
  security_hole(0);
else if (version == '12.1(11r)E2')
  security_hole(0);
else if (version == '12.1(11r)E3')
  security_hole(0);
else if (version == '12.1(12)')
  security_hole(0);
else if (version == '12.1(12a)')
  security_hole(0);
else if (version == '12.1(12b)')
  security_hole(0);
else if (version == '12.1(12c)')
  security_hole(0);
else if (version == '12.1(12c)E')
  security_hole(0);
else if (version == '12.1(12c)E1')
  security_hole(0);
else if (version == '12.1(12c)E2')
  security_hole(0);
else if (version == '12.1(12c)E3')
  security_hole(0);
else if (version == '12.1(12c)E4')
  security_hole(0);
else if (version == '12.1(12c)E5')
  security_hole(0);
else if (version == '12.1(12c)E6')
  security_hole(0);
else if (version == '12.1(12c)E7')
  security_hole(0);
else if (version == '12.1(12c)EA1')
  security_hole(0);
else if (version == '12.1(12c)EA1a')
  security_hole(0);
else if (version == '12.1(12c)EC')
  security_hole(0);
else if (version == '12.1(12c)EC1')
  security_hole(0);
else if (version == '12.1(12c)EV')
  security_hole(0);
else if (version == '12.1(12c)EV1')
  security_hole(0);
else if (version == '12.1(12c)EV2')
  security_hole(0);
else if (version == '12.1(12c)EV3')
  security_hole(0);
else if (version == '12.1(12c)EW')
  security_hole(0);
else if (version == '12.1(12c)EW1')
  security_hole(0);
else if (version == '12.1(12c)EW2')
  security_hole(0);
else if (version == '12.1(12c)EW3')
  security_hole(0);
else if (version == '12.1(12c)EW4')
  security_hole(0);
else if (version == '12.1(12c)EX')
  security_hole(0);
else if (version == '12.1(12c)EX1')
  security_hole(0);
else if (version == '12.1(12c)EY')
  security_hole(0);
else if (version == '12.1(12d)')
  security_hole(0);
else if (version == '12.1(12)E')
  security_hole(0);
else if (version == '12.1(12e)TEST2')
  security_hole(0);
else if (version == '12.1(12)EV')
  security_hole(0);
else if (version == '12.1(12r)EX')
  security_hole(0);
else if (version == '12.1(12r)EX1')
  security_hole(0);
else if (version == '12.1(12r)EZ')
  security_hole(0);
else if (version == '12.1(13)')
  security_hole(0);
else if (version == '12.1(13a)')
  security_hole(0);
else if (version == '12.1(13)AY')
  security_hole(0);
else if (version == '12.1(13)E')
  security_hole(0);
else if (version == '12.1(13)E1')
  security_hole(0);
else if (version == '12.1(13)E10')
  security_hole(0);
else if (version == '12.1(13)E11')
  security_hole(0);
else if (version == '12.1(13)E12')
  security_hole(0);
else if (version == '12.1(13)E13')
  security_hole(0);
else if (version == '12.1(13)E14')
  security_hole(0);
else if (version == '12.1(13)E15')
  security_hole(0);
else if (version == '12.1(13)E16')
  security_hole(0);
else if (version == '12.1(13)E17')
  security_hole(0);
else if (version == '12.1(13)E2')
  security_hole(0);
else if (version == '12.1(13)E3')
  security_hole(0);
else if (version == '12.1(13)E4')
  security_hole(0);
else if (version == '12.1(13)E5')
  security_hole(0);
else if (version == '12.1(13)E6')
  security_hole(0);
else if (version == '12.1(13)E7')
  security_hole(0);
else if (version == '12.1(13)E8')
  security_hole(0);
else if (version == '12.1(13)E9')
  security_hole(0);
else if (version == '12.1(13)EA1')
  security_hole(0);
else if (version == '12.1(13)EA1a')
  security_hole(0);
else if (version == '12.1(13)EA1b')
  security_hole(0);
else if (version == '12.1(13)EA1c')
  security_hole(0);
else if (version == '12.1(13)EB')
  security_hole(0);
else if (version == '12.1(13)EB1')
  security_hole(0);
else if (version == '12.1(13)EC')
  security_hole(0);
else if (version == '12.1(13)EC1')
  security_hole(0);
else if (version == '12.1(13)EC2')
  security_hole(0);
else if (version == '12.1(13)EC3')
  security_hole(0);
else if (version == '12.1(13)EC4')
  security_hole(0);
else if (version == '12.1(13e)TEST041603')
  security_hole(0);
else if (version == '12.1(13)EW')
  security_hole(0);
else if (version == '12.1(13)EW1')
  security_hole(0);
else if (version == '12.1(13)EW2')
  security_hole(0);
else if (version == '12.1(13)EW3')
  security_hole(0);
else if (version == '12.1(13)EW4')
  security_hole(0);
else if (version == '12.1(13)EX')
  security_hole(0);
else if (version == '12.1(13)EX1')
  security_hole(0);
else if (version == '12.1(13)EX2')
  security_hole(0);
else if (version == '12.1(13)EX3')
  security_hole(0);
else if (version == '12.1(13r)E1')
  security_hole(0);
else if (version == '12.1(14)')
  security_hole(0);
else if (version == '12.1(14)AX')
  security_hole(0);
else if (version == '12.1(14)AX1')
  security_hole(0);
else if (version == '12.1(14)AX2')
  security_hole(0);
else if (version == '12.1(14)AX3')
  security_hole(0);
else if (version == '12.1(14)AX4')
  security_hole(0);
else if (version == '12.1(14)AY1')
  security_hole(0);
else if (version == '12.1(14)AY2')
  security_hole(0);
else if (version == '12.1(14)AY3')
  security_hole(0);
else if (version == '12.1(14)AY4')
  security_hole(0);
else if (version == '12.1(14)AZ')
  security_hole(0);
else if (version == '12.1(14)E')
  security_hole(0);
else if (version == '12.1(14)E1')
  security_hole(0);
else if (version == '12.1(14)E10')
  security_hole(0);
else if (version == '12.1(14)E2')
  security_hole(0);
else if (version == '12.1(14)E3')
  security_hole(0);
else if (version == '12.1(14)E4')
  security_hole(0);
else if (version == '12.1(14)E5')
  security_hole(0);
else if (version == '12.1(14)E6')
  security_hole(0);
else if (version == '12.1(14)E7')
  security_hole(0);
else if (version == '12.1(14)E8')
  security_hole(0);
else if (version == '12.1(14)E9')
  security_hole(0);
else if (version == '12.1(14)EA1')
  security_hole(0);
else if (version == '12.1(14)EA1a')
  security_hole(0);
else if (version == '12.1(14)EA1b')
  security_hole(0);
else if (version == '12.1(14)EB')
  security_hole(0);
else if (version == '12.1(14)EB1')
  security_hole(0);
else if (version == '12.1(14)EO')
  security_hole(0);
else if (version == '12.1(14)EO1')
  security_hole(0);
else if (version == '12.1(14r)')
  security_hole(0);
else if (version == '12.1(14r)EO')
  security_hole(0);
else if (version == '12.1(15)')
  security_hole(0);
else if (version == '12.1(16)')
  security_hole(0);
else if (version == '12.1(17)')
  security_hole(0);
else if (version == '12.1(17a)')
  security_hole(0);
else if (version == '12.1(17r)')
  security_hole(0);
else if (version == '12.1(18)')
  security_hole(0);
else if (version == '12.1(19)')
  security_hole(0);
else if (version == '12.1(19)E')
  security_hole(0);
else if (version == '12.1(19)E1')
  security_hole(0);
else if (version == '12.1(19)E1a')
  security_hole(0);
else if (version == '12.1(19)E2')
  security_hole(0);
else if (version == '12.1(19)E3')
  security_hole(0);
else if (version == '12.1(19)E4')
  security_hole(0);
else if (version == '12.1(19)E5')
  security_hole(0);
else if (version == '12.1(19)E6')
  security_hole(0);
else if (version == '12.1(19)E7')
  security_hole(0);
else if (version == '12.1(19)EA1')
  security_hole(0);
else if (version == '12.1(19)EA1a')
  security_hole(0);
else if (version == '12.1(19)EA1b')
  security_hole(0);
else if (version == '12.1(19)EA1c')
  security_hole(0);
else if (version == '12.1(19)EA1d')
  security_hole(0);
else if (version == '12.1(19)EB')
  security_hole(0);
else if (version == '12.1(19)EC')
  security_hole(0);
else if (version == '12.1(19)EC1')
  security_hole(0);
else if (version == '12.1(19)EO')
  security_hole(0);
else if (version == '12.1(19)EO1')
  security_hole(0);
else if (version == '12.1(19)EO2')
  security_hole(0);
else if (version == '12.1(19)EO3')
  security_hole(0);
else if (version == '12.1(19)EO4')
  security_hole(0);
else if (version == '12.1(19)EO5')
  security_hole(0);
else if (version == '12.1(19)EW')
  security_hole(0);
else if (version == '12.1(19)EW1')
  security_hole(0);
else if (version == '12.1(19)EW2')
  security_hole(0);
else if (version == '12.1(19)EW3')
  security_hole(0);
else if (version == '12.1(1a)')
  security_hole(0);
else if (version == '12.1(1)AA')
  security_hole(0);
else if (version == '12.1(1)AA1')
  security_hole(0);
else if (version == '12.1(1a)T1')
  security_hole(0);
else if (version == '12.1(1b)')
  security_hole(0);
else if (version == '12.1(1c)')
  security_hole(0);
else if (version == '12.1(1)DA')
  security_hole(0);
else if (version == '12.1(1)DA1')
  security_hole(0);
else if (version == '12.1(1)DB')
  security_hole(0);
else if (version == '12.1(1)DB1')
  security_hole(0);
else if (version == '12.1(1)DB2')
  security_hole(0);
else if (version == '12.1(1)DC')
  security_hole(0);
else if (version == '12.1(1)DC1')
  security_hole(0);
else if (version == '12.1(1)DC2')
  security_hole(0);
else if (version == '12.1(1)EX')
  security_hole(0);
else if (version == '12.1(1)EX1')
  security_hole(0);
else if (version == '12.1(1)GA')
  security_hole(0);
else if (version == '12.1(1)GA1')
  security_hole(0);
else if (version == '12.1(1)PE')
  security_hole(0);
else if (version == '12.1(1r)EX')
  security_hole(0);
else if (version == '12.1(1r)XC')
  security_hole(0);
else if (version == '12.1(1r)XD')
  security_hole(0);
else if (version == '12.1(1)T')
  security_hole(0);
else if (version == '12.1(1)XA')
  security_hole(0);
else if (version == '12.1(1)XA1')
  security_hole(0);
else if (version == '12.1(1)XA2')
  security_hole(0);
else if (version == '12.1(1)XA3')
  security_hole(0);
else if (version == '12.1(1)XA4')
  security_hole(0);
else if (version == '12.1(1)XC')
  security_hole(0);
else if (version == '12.1(1)XC1')
  security_hole(0);
else if (version == '12.1(1)XD')
  security_hole(0);
else if (version == '12.1(1)XD1')
  security_hole(0);
else if (version == '12.1(1)XD2')
  security_hole(0);
else if (version == '12.1(1)XE')
  security_hole(0);
else if (version == '12.1(1)XE1')
  security_hole(0);
else if (version == '12.1(2)')
  security_hole(0);
else if (version == '12.1(20)')
  security_hole(0);
else if (version == '12.1(20a)')
  security_hole(0);
else if (version == '12.1(20)E')
  security_hole(0);
else if (version == '12.1(20)E1')
  security_hole(0);
else if (version == '12.1(20)E2')
  security_hole(0);
else if (version == '12.1(20)E3')
  security_hole(0);
else if (version == '12.1(20)E4')
  security_hole(0);
else if (version == '12.1(20)E5')
  security_hole(0);
else if (version == '12.1(20)E6')
  security_hole(0);
else if (version == '12.1(20)EA1')
  security_hole(0);
else if (version == '12.1(20)EA1a')
  security_hole(0);
else if (version == '12.1(20)EA1b')
  security_hole(0);
else if (version == '12.1(20)EA2')
  security_hole(0);
else if (version == '12.1(20)EB')
  security_hole(0);
else if (version == '12.1(20)EC')
  security_hole(0);
else if (version == '12.1(20)EC1')
  security_hole(0);
else if (version == '12.1(20)EC2')
  security_hole(0);
else if (version == '12.1(20)EC3')
  security_hole(0);
else if (version == '12.1(20)EO')
  security_hole(0);
else if (version == '12.1(20)EO1')
  security_hole(0);
else if (version == '12.1(20)EO2')
  security_hole(0);
else if (version == '12.1(20)EU')
  security_hole(0);
else if (version == '12.1(20)EU1')
  security_hole(0);
else if (version == '12.1(20)EW')
  security_hole(0);
else if (version == '12.1(20)EW1')
  security_hole(0);
else if (version == '12.1(20)EW2')
  security_hole(0);
else if (version == '12.1(20)EW3')
  security_hole(0);
else if (version == '12.1(21)')
  security_hole(0);
else if (version == '12.1(22)')
  security_hole(0);
else if (version == '12.1(22a)')
  security_hole(0);
else if (version == '12.1(22)AY')
  security_hole(0);
else if (version == '12.1(22)AY1')
  security_hole(0);
else if (version == '12.1(22)AY2')
  security_hole(0);
else if (version == '12.1(22b)')
  security_hole(0);
else if (version == '12.1(22c)')
  security_hole(0);
else if (version == '12.1(22)E')
  security_hole(0);
else if (version == '12.1(22)E1')
  security_hole(0);
else if (version == '12.1(22)E2')
  security_hole(0);
else if (version == '12.1(22)E3')
  security_hole(0);
else if (version == '12.1(22)E4')
  security_hole(0);
else if (version == '12.1(22)E5')
  security_hole(0);
else if (version == '12.1(22)E6')
  security_hole(0);
else if (version == '12.1(22)EA1')
  security_hole(0);
else if (version == '12.1(22)EA1a')
  security_hole(0);
else if (version == '12.1(22)EA1b')
  security_hole(0);
else if (version == '12.1(22)EA2')
  security_hole(0);
else if (version == '12.1(22)EA3')
  security_hole(0);
else if (version == '12.1(22)EA4')
  security_hole(0);
else if (version == '12.1(22)EA4a')
  security_hole(0);
else if (version == '12.1(22)EA5')
  security_hole(0);
else if (version == '12.1(22)EA5a')
  security_hole(0);
else if (version == '12.1(22)EA6')
  security_hole(0);
else if (version == '12.1(22)EA6a')
  security_hole(0);
else if (version == '12.1(22)EA7')
  security_hole(0);
else if (version == '12.1(22)EA8')
  security_hole(0);
else if (version == '12.1(22)EA8a')
  security_hole(0);
else if (version == '12.1(22)EB')
  security_hole(0);
else if (version == '12.1(22)EC')
  security_hole(0);
else if (version == '12.1(23)')
  security_hole(0);
else if (version == '12.1(23)E')
  security_hole(0);
else if (version == '12.1(23)E1')
  security_hole(0);
else if (version == '12.1(23)E2')
  security_hole(0);
else if (version == '12.1(23)E3')
  security_hole(0);
else if (version == '12.1(23)E4')
  security_hole(0);
else if (version == '12.1(23)EB')
  security_hole(0);
else if (version == '12.1(24)')
  security_hole(0);
else if (version == '12.1(25)')
  security_hole(0);
else if (version == '12.1(26)')
  security_hole(0);
else if (version == '12.1(26)E')
  security_hole(0);
else if (version == '12.1(26)E1')
  security_hole(0);
else if (version == '12.1(26)E2')
  security_hole(0);
else if (version == '12.1(26)E3')
  security_hole(0);
else if (version == '12.1(26)E4')
  security_hole(0);
else if (version == '12.1(26)E5')
  security_hole(0);
else if (version == '12.1(26)E6')
  security_hole(0);
else if (version == '12.1(26)E7')
  security_hole(0);
else if (version == '12.1(26)EB')
  security_hole(0);
else if (version == '12.1(26)EB1')
  security_hole(0);
else if (version == '12.1(27)')
  security_hole(0);
else if (version == '12.1(27a)')
  security_hole(0);
else if (version == '12.1(27b)')
  security_hole(0);
else if (version == '12.1(27b)E')
  security_hole(0);
else if (version == '12.1(2a)')
  security_hole(0);
else if (version == '12.1(2a)AA')
  security_hole(0);
else if (version == '12.1(2a)T1')
  security_hole(0);
else if (version == '12.1(2a)T2')
  security_hole(0);
else if (version == '12.1(2a)XH')
  security_hole(0);
else if (version == '12.1(2a)XH1')
  security_hole(0);
else if (version == '12.1(2a)XH2')
  security_hole(0);
else if (version == '12.1(2a)XH3')
  security_hole(0);
else if (version == '12.1(2b)')
  security_hole(0);
else if (version == '12.1(2)DA')
  security_hole(0);
else if (version == '12.1(2)EC')
  security_hole(0);
else if (version == '12.1(2)EC1')
  security_hole(0);
else if (version == '12.1(2)GB')
  security_hole(0);
else if (version == '12.1(2r)XD')
  security_hole(0);
else if (version == '12.1(2r)XD1')
  security_hole(0);
else if (version == '12.1(2r)XH')
  security_hole(0);
else if (version == '12.1(2)T')
  security_hole(0);
else if (version == '12.1(2)XF')
  security_hole(0);
else if (version == '12.1(2)XF1')
  security_hole(0);
else if (version == '12.1(2)XF2')
  security_hole(0);
else if (version == '12.1(2)XF3')
  security_hole(0);
else if (version == '12.1(2)XF4')
  security_hole(0);
else if (version == '12.1(2)XF5')
  security_hole(0);
else if (version == '12.1(2)XT2')
  security_hole(0);
else if (version == '12.1(3)')
  security_hole(0);
else if (version == '12.1(3a)')
  security_hole(0);
else if (version == '12.1(3)AA')
  security_hole(0);
else if (version == '12.1(3a)EC')
  security_hole(0);
else if (version == '12.1(3a)EC1')
  security_hole(0);
else if (version == '12.1(3a)T1')
  security_hole(0);
else if (version == '12.1(3a)T2')
  security_hole(0);
else if (version == '12.1(3a)T3')
  security_hole(0);
else if (version == '12.1(3a)T4')
  security_hole(0);
else if (version == '12.1(3a)T5')
  security_hole(0);
else if (version == '12.1(3a)T6')
  security_hole(0);
else if (version == '12.1(3a)T7')
  security_hole(0);
else if (version == '12.1(3a)T8')
  security_hole(0);
else if (version == '12.1(3a)XI1')
  security_hole(0);
else if (version == '12.1(3a)XI2')
  security_hole(0);
else if (version == '12.1(3a)XI3')
  security_hole(0);
else if (version == '12.1(3a)XI4')
  security_hole(0);
else if (version == '12.1(3a)XI5')
  security_hole(0);
else if (version == '12.1(3a)XI6')
  security_hole(0);
else if (version == '12.1(3a)XI7')
  security_hole(0);
else if (version == '12.1(3a)XI8')
  security_hole(0);
else if (version == '12.1(3a)XI9')
  security_hole(0);
else if (version == '12.1(3a)XL1')
  security_hole(0);
else if (version == '12.1(3a)XL2')
  security_hole(0);
else if (version == '12.1(3a)XL3')
  security_hole(0);
else if (version == '12.1(3b)')
  security_hole(0);
else if (version == '12.1(3)DA')
  security_hole(0);
else if (version == '12.1(3)DB')
  security_hole(0);
else if (version == '12.1(3)DB1')
  security_hole(0);
else if (version == '12.1(3)DC')
  security_hole(0);
else if (version == '12.1(3)DC1')
  security_hole(0);
else if (version == '12.1(3)DC2')
  security_hole(0);
else if (version == '12.1(3r)T')
  security_hole(0);
else if (version == '12.1(3r)T1')
  security_hole(0);
else if (version == '12.1(3r)T2')
  security_hole(0);
else if (version == '12.1(3r)XI1')
  security_hole(0);
else if (version == '12.1(3r)XK')
  security_hole(0);
else if (version == '12.1(3r)XL')
  security_hole(0);
else if (version == '12.1(3r)XP')
  security_hole(0);
else if (version == '12.1(3)T')
  security_hole(0);
else if (version == '12.1(3)XG')
  security_hole(0);
else if (version == '12.1(3)XG1')
  security_hole(0);
else if (version == '12.1(3)XG2')
  security_hole(0);
else if (version == '12.1(3)XG3')
  security_hole(0);
else if (version == '12.1(3)XG4')
  security_hole(0);
else if (version == '12.1(3)XG5')
  security_hole(0);
else if (version == '12.1(3)XG6')
  security_hole(0);
else if (version == '12.1(3)XI')
  security_hole(0);
else if (version == '12.1(3)XJ')
  security_hole(0);
else if (version == '12.1(3)XL')
  security_hole(0);
else if (version == '12.1(3)XP')
  security_hole(0);
else if (version == '12.1(3)XP1')
  security_hole(0);
else if (version == '12.1(3)XP2')
  security_hole(0);
else if (version == '12.1(3)XP3')
  security_hole(0);
else if (version == '12.1(3)XP4')
  security_hole(0);
else if (version == '12.1(3)XQ')
  security_hole(0);
else if (version == '12.1(3)XQ1')
  security_hole(0);
else if (version == '12.1(3)XQ2')
  security_hole(0);
else if (version == '12.1(3)XQ3')
  security_hole(0);
else if (version == '12.1(3)XS')
  security_hole(0);
else if (version == '12.1(3)XW')
  security_hole(0);
else if (version == '12.1(3)XW1')
  security_hole(0);
else if (version == '12.1(3)XW2')
  security_hole(0);
else if (version == '12.1(4)')
  security_hole(0);
else if (version == '12.1(4a)')
  security_hole(0);
else if (version == '12.1(4)AA')
  security_hole(0);
else if (version == '12.1(4b)')
  security_hole(0);
else if (version == '12.1(4c)')
  security_hole(0);
else if (version == '12.1(4)CX')
  security_hole(0);
else if (version == '12.1(4)DA')
  security_hole(0);
else if (version == '12.1(4)DB')
  security_hole(0);
else if (version == '12.1(4)DB1')
  security_hole(0);
else if (version == '12.1(4)DB2')
  security_hole(0);
else if (version == '12.1(4)EC')
  security_hole(0);
else if (version == '12.1(4)XY')
  security_hole(0);
else if (version == '12.1(4)XY1')
  security_hole(0);
else if (version == '12.1(4)XY2')
  security_hole(0);
else if (version == '12.1(4)XY3')
  security_hole(0);
else if (version == '12.1(4)XY4')
  security_hole(0);
else if (version == '12.1(4)XY5')
  security_hole(0);
else if (version == '12.1(4)XY6')
  security_hole(0);
else if (version == '12.1(4)XY7')
  security_hole(0);
else if (version == '12.1(4)XY8')
  security_hole(0);
else if (version == '12.1(4)XZ')
  security_hole(0);
else if (version == '12.1(4)XZ1')
  security_hole(0);
else if (version == '12.1(4)XZ2')
  security_hole(0);
else if (version == '12.1(4)XZ3')
  security_hole(0);
else if (version == '12.1(4)XZ4')
  security_hole(0);
else if (version == '12.1(4)XZ5')
  security_hole(0);
else if (version == '12.1(4)XZ6')
  security_hole(0);
else if (version == '12.1(4)XZ7')
  security_hole(0);
else if (version == '12.1(5)')
  security_hole(0);
else if (version == '12.1(5a)')
  security_hole(0);
else if (version == '12.1(5)AA')
  security_hole(0);
else if (version == '12.1(5b)')
  security_hole(0);
else if (version == '12.1(5c)')
  security_hole(0);
else if (version == '12.1(5c)EX')
  security_hole(0);
else if (version == '12.1(5c)EX1')
  security_hole(0);
else if (version == '12.1(5c)EX2')
  security_hole(0);
else if (version == '12.1(5c)EX3')
  security_hole(0);
else if (version == '12.1(5d)')
  security_hole(0);
else if (version == '12.1(5)DA')
  security_hole(0);
else if (version == '12.1(5)DA1')
  security_hole(0);
else if (version == '12.1(5)DB')
  security_hole(0);
else if (version == '12.1(5)DB1')
  security_hole(0);
else if (version == '12.1(5)DB2')
  security_hole(0);
else if (version == '12.1(5)DC')
  security_hole(0);
else if (version == '12.1(5)DC1')
  security_hole(0);
else if (version == '12.1(5)DC2')
  security_hole(0);
else if (version == '12.1(5)DC3')
  security_hole(0);
else if (version == '12.1(5e)')
  security_hole(0);
else if (version == '12.1(5)EC')
  security_hole(0);
else if (version == '12.1(5)EC1')
  security_hole(0);
else if (version == '12.1(5)EX')
  security_hole(0);
else if (version == '12.1(5)EY')
  security_hole(0);
else if (version == '12.1(5)EY1')
  security_hole(0);
else if (version == '12.1(5)EY2')
  security_hole(0);
else if (version == '12.1(5r)T1')
  security_hole(0);
else if (version == '12.1(5r)T2')
  security_hole(0);
else if (version == '12.1(5r)XR')
  security_hole(0);
else if (version == '12.1(5r)XR1')
  security_hole(0);
else if (version == '12.1(5r)XV')
  security_hole(0);
else if (version == '12.1(5r)YA')
  security_hole(0);
else if (version == '12.1(5)T')
  security_hole(0);
else if (version == '12.1(5)T1')
  security_hole(0);
else if (version == '12.1(5)T10')
  security_hole(0);
else if (version == '12.1(5)T11')
  security_hole(0);
else if (version == '12.1(5)T12')
  security_hole(0);
else if (version == '12.1(5)T13')
  security_hole(0);
else if (version == '12.1(5)T14')
  security_hole(0);
else if (version == '12.1(5)T15')
  security_hole(0);
else if (version == '12.1(5)T16')
  security_hole(0);
else if (version == '12.1(5)T17')
  security_hole(0);
else if (version == '12.1(5)T18')
  security_hole(0);
else if (version == '12.1(5)T19')
  security_hole(0);
else if (version == '12.1(5)T2')
  security_hole(0);
else if (version == '12.1(5)T3')
  security_hole(0);
else if (version == '12.1(5)T4')
  security_hole(0);
else if (version == '12.1(5)T5')
  security_hole(0);
else if (version == '12.1(5)T6')
  security_hole(0);
else if (version == '12.1(5)T7')
  security_hole(0);
else if (version == '12.1(5)T8')
  security_hole(0);
else if (version == '12.1(5)T8a')
  security_hole(0);
else if (version == '12.1(5)T8b')
  security_hole(0);
else if (version == '12.1(5)T8c')
  security_hole(0);
else if (version == '12.1(5)T9')
  security_hole(0);
else if (version == '12.1(5)XM')
  security_hole(0);
else if (version == '12.1(5)XM1')
  security_hole(0);
else if (version == '12.1(5)XM2')
  security_hole(0);
else if (version == '12.1(5)XM3')
  security_hole(0);
else if (version == '12.1(5)XM4')
  security_hole(0);
else if (version == '12.1(5)XM5')
  security_hole(0);
else if (version == '12.1(5)XM6')
  security_hole(0);
else if (version == '12.1(5)XM7')
  security_hole(0);
else if (version == '12.1(5)XM8')
  security_hole(0);
else if (version == '12.1(5)XR')
  security_hole(0);
else if (version == '12.1(5)XR1')
  security_hole(0);
else if (version == '12.1(5)XR2')
  security_hole(0);
else if (version == '12.1(5)XS')
  security_hole(0);
else if (version == '12.1(5)XS1')
  security_hole(0);
else if (version == '12.1(5)XS2')
  security_hole(0);
else if (version == '12.1(5)XS3')
  security_hole(0);
else if (version == '12.1(5)XS4')
  security_hole(0);
else if (version == '12.1(5)XS5')
  security_hole(0);
else if (version == '12.1(5)XU')
  security_hole(0);
else if (version == '12.1(5)XU1')
  security_hole(0);
else if (version == '12.1(5)XU2')
  security_hole(0);
else if (version == '12.1(5)XV')
  security_hole(0);
else if (version == '12.1(5)XV1')
  security_hole(0);
else if (version == '12.1(5)XV2')
  security_hole(0);
else if (version == '12.1(5)XV3')
  security_hole(0);
else if (version == '12.1(5)XV4')
  security_hole(0);
else if (version == '12.1(5)XX')
  security_hole(0);
else if (version == '12.1(5)XX1')
  security_hole(0);
else if (version == '12.1(5)XX2')
  security_hole(0);
else if (version == '12.1(5)XX3')
  security_hole(0);
else if (version == '12.1(5)YA')
  security_hole(0);
else if (version == '12.1(5)YA1')
  security_hole(0);
else if (version == '12.1(5)YA2')
  security_hole(0);
else if (version == '12.1(5)YB')
  security_hole(0);
else if (version == '12.1(5)YB1')
  security_hole(0);
else if (version == '12.1(5)YB2')
  security_hole(0);
else if (version == '12.1(5)YB3')
  security_hole(0);
else if (version == '12.1(5)YB4')
  security_hole(0);
else if (version == '12.1(5)YB5')
  security_hole(0);
else if (version == '12.1(5)YC')
  security_hole(0);
else if (version == '12.1(5)YC1')
  security_hole(0);
else if (version == '12.1(5)YC2')
  security_hole(0);
else if (version == '12.1(5)YC3')
  security_hole(0);
else if (version == '12.1(5)YD')
  security_hole(0);
else if (version == '12.1(5)YD1')
  security_hole(0);
else if (version == '12.1(5)YD2')
  security_hole(0);
else if (version == '12.1(5)YD3')
  security_hole(0);
else if (version == '12.1(5)YD4')
  security_hole(0);
else if (version == '12.1(5)YD5')
  security_hole(0);
else if (version == '12.1(5)YD6')
  security_hole(0);
else if (version == '12.1(6)')
  security_hole(0);
else if (version == '12.1(6a)')
  security_hole(0);
else if (version == '12.1(6)AA')
  security_hole(0);
else if (version == '12.1(6b)')
  security_hole(0);
else if (version == '12.1(6)DA')
  security_hole(0);
else if (version == '12.1(6)DA1')
  security_hole(0);
else if (version == '12.1(6)DA2')
  security_hole(0);
else if (version == '12.1(6)EA1')
  security_hole(0);
else if (version == '12.1(6)EA1a')
  security_hole(0);
else if (version == '12.1(6)EC')
  security_hole(0);
else if (version == '12.1(6)EC1')
  security_hole(0);
else if (version == '12.1(6e)PE1')
  security_hole(0);
else if (version == '12.1(6)EX')
  security_hole(0);
else if (version == '12.1(6)EY')
  security_hole(0);
else if (version == '12.1(6)EY1')
  security_hole(0);
else if (version == '12.1(6)EZ')
  security_hole(0);
else if (version == '12.1(6)EZ1')
  security_hole(0);
else if (version == '12.1(6)EZ2')
  security_hole(0);
else if (version == '12.1(6)EZ3')
  security_hole(0);
else if (version == '12.1(6)EZ4')
  security_hole(0);
else if (version == '12.1(6)EZ5')
  security_hole(0);
else if (version == '12.1(6)EZ6')
  security_hole(0);
else if (version == '12.1(6)EZ7')
  security_hole(0);
else if (version == '12.1(6)EZ8')
  security_hole(0);
else if (version == '12.1(6r)DA')
  security_hole(0);
else if (version == '12.1(7)')
  security_hole(0);
else if (version == '12.1(7a)')
  security_hole(0);
else if (version == '12.1(7)AA')
  security_hole(0);
else if (version == '12.1(7a)EY')
  security_hole(0);
else if (version == '12.1(7a)EY1')
  security_hole(0);
else if (version == '12.1(7a)EY2')
  security_hole(0);
else if (version == '12.1(7a)EY3')
  security_hole(0);
else if (version == '12.1(7b)')
  security_hole(0);
else if (version == '12.1(7c)')
  security_hole(0);
else if (version == '12.1(7)CX')
  security_hole(0);
else if (version == '12.1(7)CX1')
  security_hole(0);
else if (version == '12.1(7)DA')
  security_hole(0);
else if (version == '12.1(7)DA1')
  security_hole(0);
else if (version == '12.1(7)DA2')
  security_hole(0);
else if (version == '12.1(7)DA3')
  security_hole(0);
else if (version == '12.1(7)EC')
  security_hole(0);
else if (version == '12.1(8)')
  security_hole(0);
else if (version == '12.1(8a)')
  security_hole(0);
else if (version == '12.1(8)AA')
  security_hole(0);
else if (version == '12.1(8)AA1')
  security_hole(0);
else if (version == '12.1(8a)EW')
  security_hole(0);
else if (version == '12.1(8a)EW1')
  security_hole(0);
else if (version == '12.1(8a)EX')
  security_hole(0);
else if (version == '12.1(8a)EX1')
  security_hole(0);
else if (version == '12.1(8b)')
  security_hole(0);
else if (version == '12.1(8b)EX2')
  security_hole(0);
else if (version == '12.1(8b)EX3')
  security_hole(0);
else if (version == '12.1(8b)EX4')
  security_hole(0);
else if (version == '12.1(8b)EX5')
  security_hole(0);
else if (version == '12.1(8c)')
  security_hole(0);
else if (version == '12.1(8)EA1')
  security_hole(0);
else if (version == '12.1(8)EA1b')
  security_hole(0);
else if (version == '12.1(8)EA1c')
  security_hole(0);
else if (version == '12.1(8)EC')
  security_hole(0);
else if (version == '12.1(8)EC1')
  security_hole(0);
else if (version == '12.1(8e)NAT001')
  security_hole(0);
else if (version == '12.1(8)EX')
  security_hole(0);
else if (version == '12.1(9)')
  security_hole(0);
else if (version == '12.1(9a)')
  security_hole(0);
else if (version == '12.1(9)EA1')
  security_hole(0);
else if (version == '12.1(9)EA1a')
  security_hole(0);
else if (version == '12.1(9)EA1c')
  security_hole(0);
else if (version == '12.1(9)EA1d')
  security_hole(0);
else if (version == '12.1(9)EC')
  security_hole(0);
else if (version == '12.1(9)EC1')
  security_hole(0);
else if (version == '12.1(9)EX')
  security_hole(0);
else if (version == '12.1(9)EX1')
  security_hole(0);
else if (version == '12.1(9)EX2')
  security_hole(0);
else if (version == '12.1(9)EX3')
  security_hole(0);
else if (version == '12.1(9r)EX')
  security_hole(0);
else if (version == '12.2(1)')
  security_hole(0);
else if (version == '12.2(10)')
  security_hole(0);
else if (version == '12.2(10a)')
  security_hole(0);
else if (version == '12.2(10b)')
  security_hole(0);
else if (version == '12.2(10c)')
  security_hole(0);
else if (version == '12.2(10d)')
  security_hole(0);
else if (version == '12.2(10)DA')
  security_hole(0);
else if (version == '12.2(10)DA1')
  security_hole(0);
else if (version == '12.2(10)DA2')
  security_hole(0);
else if (version == '12.2(10)DA3')
  security_hole(0);
else if (version == '12.2(10)DA4')
  security_hole(0);
else if (version == '12.2(10)DA5')
  security_hole(0);
else if (version == '12.2(10e)')
  security_hole(0);
else if (version == '12.2(10f)')
  security_hole(0);
else if (version == '12.2(10g)')
  security_hole(0);
else if (version == '12.2(10r)')
  security_hole(0);
else if (version == '12.2(11)BC1')
  security_hole(0);
else if (version == '12.2(11)BC1a')
  security_hole(0);
else if (version == '12.2(11)BC1b')
  security_hole(0);
else if (version == '12.2(11)BC2')
  security_hole(0);
else if (version == '12.2(11)BC2a')
  security_hole(0);
else if (version == '12.2(11)BC3')
  security_hole(0);
else if (version == '12.2(11)BC3a')
  security_hole(0);
else if (version == '12.2(11)BC3b')
  security_hole(0);
else if (version == '12.2(11)BC3c')
  security_hole(0);
else if (version == '12.2(11)BC3d')
  security_hole(0);
else if (version == '12.2(11)CX')
  security_hole(0);
else if (version == '12.2(11)CX1')
  security_hole(0);
else if (version == '12.2(11)CY')
  security_hole(0);
else if (version == '12.2(11)JA')
  security_hole(0);
else if (version == '12.2(11)JA1')
  security_hole(0);
else if (version == '12.2(11)JA2')
  security_hole(0);
else if (version == '12.2(11)JA3')
  security_hole(0);
else if (version == '12.2(11r)T')
  security_hole(0);
else if (version == '12.2(11r)T1')
  security_hole(0);
else if (version == '12.2(11r)YS1')
  security_hole(0);
else if (version == '12.2(11)S')
  security_hole(0);
else if (version == '12.2(11)S1')
  security_hole(0);
else if (version == '12.2(11)S2')
  security_hole(0);
else if (version == '12.2(11)S3')
  security_hole(0);
else if (version == '12.2(11)T')
  security_hole(0);
else if (version == '12.2(11)T1')
  security_hole(0);
else if (version == '12.2(11)T10')
  security_hole(0);
else if (version == '12.2(11)T11')
  security_hole(0);
else if (version == '12.2(11)T2')
  security_hole(0);
else if (version == '12.2(11)T3')
  security_hole(0);
else if (version == '12.2(11)T4')
  security_hole(0);
else if (version == '12.2(11)T5')
  security_hole(0);
else if (version == '12.2(11)T6')
  security_hole(0);
else if (version == '12.2(11)T7')
  security_hole(0);
else if (version == '12.2(11)T8')
  security_hole(0);
else if (version == '12.2(11)T9')
  security_hole(0);
else if (version == '12.2(11)YP1')
  security_hole(0);
else if (version == '12.2(11)YP2')
  security_hole(0);
else if (version == '12.2(11)YP3')
  security_hole(0);
else if (version == '12.2(11)YP4')
  security_hole(0);
else if (version == '12.2(11)YP5')
  security_hole(0);
else if (version == '12.2(11)YS021223')
  security_hole(0);
else if (version == '12.2(11)ZC')
  security_hole(0);
else if (version == '12.2(1a)')
  security_hole(0);
else if (version == '12.2(1a)XC')
  security_hole(0);
else if (version == '12.2(1a)XC1')
  security_hole(0);
else if (version == '12.2(1a)XC2')
  security_hole(0);
else if (version == '12.2(1a)XC3')
  security_hole(0);
else if (version == '12.2(1a)XC4')
  security_hole(0);
else if (version == '12.2(1a)XC5')
  security_hole(0);
else if (version == '12.2(1b)')
  security_hole(0);
else if (version == '12.2(1b)DA')
  security_hole(0);
else if (version == '12.2(1b)DA1')
  security_hole(0);
else if (version == '12.2(1c)')
  security_hole(0);
else if (version == '12.2(1d)')
  security_hole(0);
else if (version == '12.2(1)DX')
  security_hole(0);
else if (version == '12.2(1)DX1')
  security_hole(0);
else if (version == '12.2(1)MB1')
  security_hole(0);
else if (version == '12.2(1r)')
  security_hole(0);
else if (version == '12.2(1r)DD')
  security_hole(0);
else if (version == '12.2(1r)DD1')
  security_hole(0);
else if (version == '12.2(1r)T')
  security_hole(0);
else if (version == '12.2(1r)T1')
  security_hole(0);
else if (version == '12.2(1r)XA')
  security_hole(0);
else if (version == '12.2(1r)XE')
  security_hole(0);
else if (version == '12.2(1r)XE1')
  security_hole(0);
else if (version == '12.2(1r)XE2')
  security_hole(0);
else if (version == '12.2(1)XD')
  security_hole(0);
else if (version == '12.2(1)XD1')
  security_hole(0);
else if (version == '12.2(1)XD2')
  security_hole(0);
else if (version == '12.2(1)XD3')
  security_hole(0);
else if (version == '12.2(1)XD4')
  security_hole(0);
else if (version == '12.2(1)XE')
  security_hole(0);
else if (version == '12.2(1)XE1')
  security_hole(0);
else if (version == '12.2(1)XE2')
  security_hole(0);
else if (version == '12.2(1)XS')
  security_hole(0);
else if (version == '12.2(1)XS1')
  security_hole(0);
else if (version == '12.2(1)XS1a')
  security_hole(0);
else if (version == '12.2(1)XS2')
  security_hole(0);
else if (version == '12.2(2)B')
  security_hole(0);
else if (version == '12.2(2)B1')
  security_hole(0);
else if (version == '12.2(2)B2')
  security_hole(0);
else if (version == '12.2(2)B3')
  security_hole(0);
else if (version == '12.2(2)B4')
  security_hole(0);
else if (version == '12.2(2)B5')
  security_hole(0);
else if (version == '12.2(2)B6')
  security_hole(0);
else if (version == '12.2(2)B7')
  security_hole(0);
else if (version == '12.2(2b)REG1')
  security_hole(0);
else if (version == '12.2(2)BX')
  security_hole(0);
else if (version == '12.2(2)BX1')
  security_hole(0);
else if (version == '12.2(2)BX2')
  security_hole(0);
else if (version == '12.2(2)DD')
  security_hole(0);
else if (version == '12.2(2)DD1')
  security_hole(0);
else if (version == '12.2(2)DD2')
  security_hole(0);
else if (version == '12.2(2)DD3')
  security_hole(0);
else if (version == '12.2(2)DD4')
  security_hole(0);
else if (version == '12.2(2)DX')
  security_hole(0);
else if (version == '12.2(2)DX1')
  security_hole(0);
else if (version == '12.2(2)DX2')
  security_hole(0);
else if (version == '12.2(2)DX3')
  security_hole(0);
else if (version == '12.2(2r)')
  security_hole(0);
else if (version == '12.2(2r)B7')
  security_hole(0);
else if (version == '12.2(2r)B8')
  security_hole(0);
else if (version == '12.2(2r)DD')
  security_hole(0);
else if (version == '12.2(2r)T')
  security_hole(0);
else if (version == '12.2(2r)T1')
  security_hole(0);
else if (version == '12.2(2r)T2')
  security_hole(0);
else if (version == '12.2(2r)XA')
  security_hole(0);
else if (version == '12.2(2r)XB')
  security_hole(0);
else if (version == '12.2(2r)XB5')
  security_hole(0);
else if (version == '12.2(2r)XT')
  security_hole(0);
else if (version == '12.2(2)T')
  security_hole(0);
else if (version == '12.2(2)T1')
  security_hole(0);
else if (version == '12.2(2)T2')
  security_hole(0);
else if (version == '12.2(2)T3')
  security_hole(0);
else if (version == '12.2(2)T4')
  security_hole(0);
else if (version == '12.2(2)XA')
  security_hole(0);
else if (version == '12.2(2)XA1')
  security_hole(0);
else if (version == '12.2(2)XA2')
  security_hole(0);
else if (version == '12.2(2)XA3')
  security_hole(0);
else if (version == '12.2(2)XA4')
  security_hole(0);
else if (version == '12.2(2)XA5')
  security_hole(0);
else if (version == '12.2(2)XB')
  security_hole(0);
else if (version == '12.2(2)XB1')
  security_hole(0);
else if (version == '12.2(2)XB10')
  security_hole(0);
else if (version == '12.2(2)XB11')
  security_hole(0);
else if (version == '12.2(2)XB12')
  security_hole(0);
else if (version == '12.2(2)XB14')
  security_hole(0);
else if (version == '12.2(2)XB15')
  security_hole(0);
else if (version == '12.2(2)XB16')
  security_hole(0);
else if (version == '12.2(2)XB17')
  security_hole(0);
else if (version == '12.2(2)XB18')
  security_hole(0);
else if (version == '12.2(2)XB2')
  security_hole(0);
else if (version == '12.2(2)XB3')
  security_hole(0);
else if (version == '12.2(2)XB4')
  security_hole(0);
else if (version == '12.2(2)XB4b')
  security_hole(0);
else if (version == '12.2(2)XB5')
  security_hole(0);
else if (version == '12.2(2)XB6')
  security_hole(0);
else if (version == '12.2(2)XB6a')
  security_hole(0);
else if (version == '12.2(2)XB6b')
  security_hole(0);
else if (version == '12.2(2)XB6c')
  security_hole(0);
else if (version == '12.2(2)XB6d')
  security_hole(0);
else if (version == '12.2(2)XB7')
  security_hole(0);
else if (version == '12.2(2)XB8')
  security_hole(0);
else if (version == '12.2(2)XB9')
  security_hole(0);
else if (version == '12.2(2)XC')
  security_hole(0);
else if (version == '12.2(2)XC1')
  security_hole(0);
else if (version == '12.2(2)XC2')
  security_hole(0);
else if (version == '12.2(2)XC3')
  security_hole(0);
else if (version == '12.2(2)XC4')
  security_hole(0);
else if (version == '12.2(2)XC5')
  security_hole(0);
else if (version == '12.2(2)XC6')
  security_hole(0);
else if (version == '12.2(2)XC7')
  security_hole(0);
else if (version == '12.2(2)XF')
  security_hole(0);
else if (version == '12.2(2)XF1')
  security_hole(0);
else if (version == '12.2(2)XF2')
  security_hole(0);
else if (version == '12.2(2)XG')
  security_hole(0);
else if (version == '12.2(2)XG1')
  security_hole(0);
else if (version == '12.2(2)XH')
  security_hole(0);
else if (version == '12.2(2)XH1')
  security_hole(0);
else if (version == '12.2(2)XH2')
  security_hole(0);
else if (version == '12.2(2)XI')
  security_hole(0);
else if (version == '12.2(2)XI1')
  security_hole(0);
else if (version == '12.2(2)XI2')
  security_hole(0);
else if (version == '12.2(2)XJ')
  security_hole(0);
else if (version == '12.2(2)XK')
  security_hole(0);
else if (version == '12.2(2)XK1')
  security_hole(0);
else if (version == '12.2(2)XK2')
  security_hole(0);
else if (version == '12.2(2)XK3')
  security_hole(0);
else if (version == '12.2(2)XN')
  security_hole(0);
else if (version == '12.2(2)XQ')
  security_hole(0);
else if (version == '12.2(2)XQ1')
  security_hole(0);
else if (version == '12.2(2)XR')
  security_hole(0);
else if (version == '12.2(2)XT')
  security_hole(0);
else if (version == '12.2(2)XT1')
  security_hole(0);
else if (version == '12.2(2)XT2')
  security_hole(0);
else if (version == '12.2(2)XT3')
  security_hole(0);
else if (version == '12.2(2)XU')
  security_hole(0);
else if (version == '12.2(2)XU1')
  security_hole(0);
else if (version == '12.2(2)XU2')
  security_hole(0);
else if (version == '12.2(2)XU3')
  security_hole(0);
else if (version == '12.2(2)XU4')
  security_hole(0);
else if (version == '12.2(2)YC')
  security_hole(0);
else if (version == '12.2(2)YC1')
  security_hole(0);
else if (version == '12.2(2)YC2')
  security_hole(0);
else if (version == '12.2(2)YC3')
  security_hole(0);
else if (version == '12.2(2)YC4')
  security_hole(0);
else if (version == '12.2(2)YK')
  security_hole(0);
else if (version == '12.2(2)YK1')
  security_hole(0);
else if (version == '12.2(3)')
  security_hole(0);
else if (version == '12.2(3a)')
  security_hole(0);
else if (version == '12.2(3b)')
  security_hole(0);
else if (version == '12.2(3c)')
  security_hole(0);
else if (version == '12.2(3d)')
  security_hole(0);
else if (version == '12.2(3e)')
  security_hole(0);
else if (version == '12.2(3f)')
  security_hole(0);
else if (version == '12.2(3g)')
  security_hole(0);
else if (version == '12.2(4)B')
  security_hole(0);
else if (version == '12.2(4)B1')
  security_hole(0);
else if (version == '12.2(4)B2')
  security_hole(0);
else if (version == '12.2(4)B3')
  security_hole(0);
else if (version == '12.2(4)B4')
  security_hole(0);
else if (version == '12.2(4)B5')
  security_hole(0);
else if (version == '12.2(4)B6')
  security_hole(0);
else if (version == '12.2(4)B7')
  security_hole(0);
else if (version == '12.2(4)B7a')
  security_hole(0);
else if (version == '12.2(4)B8')
  security_hole(0);
else if (version == '12.2(4)BC1')
  security_hole(0);
else if (version == '12.2(4)BC1a')
  security_hole(0);
else if (version == '12.2(4)BC1b')
  security_hole(0);
else if (version == '12.2(4)BW')
  security_hole(0);
else if (version == '12.2(4)BW1')
  security_hole(0);
else if (version == '12.2(4)BW1a')
  security_hole(0);
else if (version == '12.2(4)BW2')
  security_hole(0);
else if (version == '12.2(4)BX')
  security_hole(0);
else if (version == '12.2(4)BX1')
  security_hole(0);
else if (version == '12.2(4)BX1a')
  security_hole(0);
else if (version == '12.2(4)BX1b')
  security_hole(0);
else if (version == '12.2(4)BX1c')
  security_hole(0);
else if (version == '12.2(4)BX1d')
  security_hole(0);
else if (version == '12.2(4)BX2')
  security_hole(0);
else if (version == '12.2(4)BY')
  security_hole(0);
else if (version == '12.2(4)BY1')
  security_hole(0);
else if (version == '12.2(4)JA')
  security_hole(0);
else if (version == '12.2(4)JA1')
  security_hole(0);
else if (version == '12.2(4)MB1')
  security_hole(0);
else if (version == '12.2(4)MB10')
  security_hole(0);
else if (version == '12.2(4)MB11')
  security_hole(0);
else if (version == '12.2(4)MB12')
  security_hole(0);
else if (version == '12.2(4)MB13')
  security_hole(0);
else if (version == '12.2(4)MB13a')
  security_hole(0);
else if (version == '12.2(4)MB13b')
  security_hole(0);
else if (version == '12.2(4)MB13c')
  security_hole(0);
else if (version == '12.2(4)MB2')
  security_hole(0);
else if (version == '12.2(4)MB3')
  security_hole(0);
else if (version == '12.2(4)MB4')
  security_hole(0);
else if (version == '12.2(4)MB5')
  security_hole(0);
else if (version == '12.2(4)MB6')
  security_hole(0);
else if (version == '12.2(4)MB7')
  security_hole(0);
else if (version == '12.2(4)MB8')
  security_hole(0);
else if (version == '12.2(4)MB9')
  security_hole(0);
else if (version == '12.2(4)MB9a')
  security_hole(0);
else if (version == '12.2(4)MX')
  security_hole(0);
else if (version == '12.2(4)MX1')
  security_hole(0);
else if (version == '12.2(4)MX2')
  security_hole(0);
else if (version == '12.2(4r)B')
  security_hole(0);
else if (version == '12.2(4r)B1')
  security_hole(0);
else if (version == '12.2(4r)B2')
  security_hole(0);
else if (version == '12.2(4r)B3')
  security_hole(0);
else if (version == '12.2(4r)B4')
  security_hole(0);
else if (version == '12.2(4r)T')
  security_hole(0);
else if (version == '12.2(4r)T1')
  security_hole(0);
else if (version == '12.2(4r)XL')
  security_hole(0);
else if (version == '12.2(4r)XM')
  security_hole(0);
else if (version == '12.2(4r)XM1')
  security_hole(0);
else if (version == '12.2(4r)XM2')
  security_hole(0);
else if (version == '12.2(4r)XM3')
  security_hole(0);
else if (version == '12.2(4r)XM4')
  security_hole(0);
else if (version == '12.2(4r)XT')
  security_hole(0);
else if (version == '12.2(4r)XT1')
  security_hole(0);
else if (version == '12.2(4r)XT2')
  security_hole(0);
else if (version == '12.2(4r)XT3')
  security_hole(0);
else if (version == '12.2(4r)XT4')
  security_hole(0);
else if (version == '12.2(4)T')
  security_hole(0);
else if (version == '12.2(4)T1')
  security_hole(0);
else if (version == '12.2(4)T2')
  security_hole(0);
else if (version == '12.2(4)T3')
  security_hole(0);
else if (version == '12.2(4)T4')
  security_hole(0);
else if (version == '12.2(4)T5')
  security_hole(0);
else if (version == '12.2(4)T6')
  security_hole(0);
else if (version == '12.2(4)T7')
  security_hole(0);
else if (version == '12.2(4)XF')
  security_hole(0);
else if (version == '12.2(4)XF1')
  security_hole(0);
else if (version == '12.2(4)XL')
  security_hole(0);
else if (version == '12.2(4)XL1')
  security_hole(0);
else if (version == '12.2(4)XL2')
  security_hole(0);
else if (version == '12.2(4)XL3')
  security_hole(0);
else if (version == '12.2(4)XL4')
  security_hole(0);
else if (version == '12.2(4)XL5')
  security_hole(0);
else if (version == '12.2(4)XL6')
  security_hole(0);
else if (version == '12.2(4)XM')
  security_hole(0);
else if (version == '12.2(4)XM1')
  security_hole(0);
else if (version == '12.2(4)XM2')
  security_hole(0);
else if (version == '12.2(4)XM3')
  security_hole(0);
else if (version == '12.2(4)XM4')
  security_hole(0);
else if (version == '12.2(4)XR')
  security_hole(0);
else if (version == '12.2(4)XV')
  security_hole(0);
else if (version == '12.2(4)XV1')
  security_hole(0);
else if (version == '12.2(4)XV2')
  security_hole(0);
else if (version == '12.2(4)XV3')
  security_hole(0);
else if (version == '12.2(4)XV4')
  security_hole(0);
else if (version == '12.2(4)XV4a')
  security_hole(0);
else if (version == '12.2(4)XV5')
  security_hole(0);
else if (version == '12.2(4)XW')
  security_hole(0);
else if (version == '12.2(4)XZ')
  security_hole(0);
else if (version == '12.2(4)XZ1')
  security_hole(0);
else if (version == '12.2(4)XZ2')
  security_hole(0);
else if (version == '12.2(4)XZ3')
  security_hole(0);
else if (version == '12.2(4)XZ4')
  security_hole(0);
else if (version == '12.2(4)XZ5')
  security_hole(0);
else if (version == '12.2(4)XZ6')
  security_hole(0);
else if (version == '12.2(4)XZ7')
  security_hole(0);
else if (version == '12.2(4)YA')
  security_hole(0);
else if (version == '12.2(4)YA1')
  security_hole(0);
else if (version == '12.2(4)YA10')
  security_hole(0);
else if (version == '12.2(4)YA11')
  security_hole(0);
else if (version == '12.2(4)YA2')
  security_hole(0);
else if (version == '12.2(4)YA3')
  security_hole(0);
else if (version == '12.2(4)YA4')
  security_hole(0);
else if (version == '12.2(4)YA5')
  security_hole(0);
else if (version == '12.2(4)YA6')
  security_hole(0);
else if (version == '12.2(4)YA7')
  security_hole(0);
else if (version == '12.2(4)YA8')
  security_hole(0);
else if (version == '12.2(4)YA9')
  security_hole(0);
else if (version == '12.2(4)YB')
  security_hole(0);
else if (version == '12.2(4)YF')
  security_hole(0);
else if (version == '12.2(4)YH')
  security_hole(0);
else if (version == '12.2(5)')
  security_hole(0);
else if (version == '12.2(5a)')
  security_hole(0);
else if (version == '12.2(5b)')
  security_hole(0);
else if (version == '12.2(5c)')
  security_hole(0);
else if (version == '12.2(5d)')
  security_hole(0);
else if (version == '12.2(5)DA')
  security_hole(0);
else if (version == '12.2(5)DA1')
  security_hole(0);
else if (version == '12.2(6)')
  security_hole(0);
else if (version == '12.2(6a)')
  security_hole(0);
else if (version == '12.2(6b)')
  security_hole(0);
else if (version == '12.2(6c)')
  security_hole(0);
else if (version == '12.2(6c)M1')
  security_hole(0);
else if (version == '12.2(6c)TEST')
  security_hole(0);
else if (version == '12.2(6d)')
  security_hole(0);
else if (version == '12.2(6e)')
  security_hole(0);
else if (version == '12.2(6f)')
  security_hole(0);
else if (version == '12.2(6f)M1')
  security_hole(0);
else if (version == '12.2(6g)')
  security_hole(0);
else if (version == '12.2(6h)')
  security_hole(0);
else if (version == '12.2(6i)')
  security_hole(0);
else if (version == '12.2(6j)')
  security_hole(0);
else if (version == '12.2(6r)')
  security_hole(0);
else if (version == '12.2(7)')
  security_hole(0);
else if (version == '12.2(7a)')
  security_hole(0);
else if (version == '12.2(7b)')
  security_hole(0);
else if (version == '12.2(7c)')
  security_hole(0);
else if (version == '12.2(7d)')
  security_hole(0);
else if (version == '12.2(7)DA')
  security_hole(0);
else if (version == '12.2(7e)')
  security_hole(0);
else if (version == '12.2(7f)')
  security_hole(0);
else if (version == '12.2(7g)')
  security_hole(0);
else if (version == '12.2(7r)')
  security_hole(0);
else if (version == '12.2(7r)EY')
  security_hole(0);
else if (version == '12.2(7r)XM')
  security_hole(0);
else if (version == '12.2(7r)XM1')
  security_hole(0);
else if (version == '12.2(7r)XM2')
  security_hole(0);
else if (version == '12.2(7r)XM3')
  security_hole(0);
else if (version == '12.2(7r)XM4')
  security_hole(0);
else if (version == '12.2(7r)XM5')
  security_hole(0);
else if (version == '12.2(8)B')
  security_hole(0);
else if (version == '12.2(8)B1')
  security_hole(0);
else if (version == '12.2(8)B2')
  security_hole(0);
else if (version == '12.2(8)BC1')
  security_hole(0);
else if (version == '12.2(8)BC2')
  security_hole(0);
else if (version == '12.2(8)BC2a')
  security_hole(0);
else if (version == '12.2(8)BY')
  security_hole(0);
else if (version == '12.2(8)BY1')
  security_hole(0);
else if (version == '12.2(8)BY2')
  security_hole(0);
else if (version == '12.2(8)BZ')
  security_hole(0);
else if (version == '12.2(8)JA')
  security_hole(0);
else if (version == '12.2(8)MC1')
  security_hole(0);
else if (version == '12.2(8)MC2')
  security_hole(0);
else if (version == '12.2(8)MC2a')
  security_hole(0);
else if (version == '12.2(8)MC2b')
  security_hole(0);
else if (version == '12.2(8)MC2c')
  security_hole(0);
else if (version == '12.2(8)MC2d')
  security_hole(0);
else if (version == '12.2(8r)')
  security_hole(0);
else if (version == '12.2(8r)B')
  security_hole(0);
else if (version == '12.2(8r)B1')
  security_hole(0);
else if (version == '12.2(8r)B2')
  security_hole(0);
else if (version == '12.2(8r)B3')
  security_hole(0);
else if (version == '12.2(8r)B3a')
  security_hole(0);
else if (version == '12.2(8r)MC1')
  security_hole(0);
else if (version == '12.2(8r)MC2')
  security_hole(0);
else if (version == '12.2(8r)MC3')
  security_hole(0);
else if (version == '12.2(8r)T')
  security_hole(0);
else if (version == '12.2(8r)T1')
  security_hole(0);
else if (version == '12.2(8r)T2')
  security_hole(0);
else if (version == '12.2(8r)T3')
  security_hole(0);
else if (version == '12.2(8)T')
  security_hole(0);
else if (version == '12.2(8)T0a')
  security_hole(0);
else if (version == '12.2(8)T0b')
  security_hole(0);
else if (version == '12.2(8)T0c')
  security_hole(0);
else if (version == '12.2(8)T0d')
  security_hole(0);
else if (version == '12.2(8)T0e')
  security_hole(0);
else if (version == '12.2(8)T1')
  security_hole(0);
else if (version == '12.2(8)T10')
  security_hole(0);
else if (version == '12.2(8)T2')
  security_hole(0);
else if (version == '12.2(8)T3')
  security_hole(0);
else if (version == '12.2(8)T4')
  security_hole(0);
else if (version == '12.2(8)T4a')
  security_hole(0);
else if (version == '12.2(8)T5')
  security_hole(0);
else if (version == '12.2(8)T6')
  security_hole(0);
else if (version == '12.2(8)T7')
  security_hole(0);
else if (version == '12.2(8)T8')
  security_hole(0);
else if (version == '12.2(8)T9')
  security_hole(0);
else if (version == '12.2(8)TPC10a')
  security_hole(0);
else if (version == '12.2(8)YD')
  security_hole(0);
else if (version == '12.2(8)YD1')
  security_hole(0);
else if (version == '12.2(8)YD2')
  security_hole(0);
else if (version == '12.2(8)YD3')
  security_hole(0);
else if (version == '12.2(8)YJ')
  security_hole(0);
else if (version == '12.2(8)YJ1')
  security_hole(0);
else if (version == '12.2(8)YY')
  security_hole(0);
else if (version == '12.2(8)YY1')
  security_hole(0);
else if (version == '12.2(8)YY2')
  security_hole(0);
else if (version == '12.2(8)YY3')
  security_hole(0);
else if (version == '12.2(8)YY4')
  security_hole(0);
else if (version == '12.2(8)ZB')
  security_hole(0);
else if (version == '12.2(8)ZB1')
  security_hole(0);
else if (version == '12.2(8)ZB2')
  security_hole(0);
else if (version == '12.2(8)ZB3')
  security_hole(0);
else if (version == '12.2(8)ZB4')
  security_hole(0);
else if (version == '12.2(8)ZB4a')
  security_hole(0);
else if (version == '12.2(8)ZB5')
  security_hole(0);
else if (version == '12.2(8)ZB6')
  security_hole(0);
else if (version == '12.2(8)ZB7')
  security_hole(0);
else if (version == '12.2(8)ZB8')
  security_hole(0);
else if (version == '12.2(99r)B')
  security_hole(0);
else if (version == '12.2(9)S')
  security_hole(0);
else if (version == '12.2(9)YE')
  security_hole(0);
else if (version == '12.2(9)YO')
  security_hole(0);
else if (version == '12.2(9)YO1')
  security_hole(0);
else if (version == '12.2(9)YO2')
  security_hole(0);
else if (version == '12.2(9)YO3')
  security_hole(0);
else if (version == '12.2(9)YO4')
  security_hole(0);
else if (version == '12.2(9)ZA')
  security_hole(0);
else if (version == '12.3(10r)')
  security_hole(0);
else if (version == '12.9(9)S0225')
  security_hole(0);
else
  audit(AUDIT_HOST_NOT, 'affected');
