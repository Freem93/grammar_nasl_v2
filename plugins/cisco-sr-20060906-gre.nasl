#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17789);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/11 19:44:18 $");

  script_cve_id("CVE-2006-4650");
  script_osvdb_id(28590);
  script_xref(name:"CISCO-BUG-ID", value:"CSCea22552");
  script_xref(name:"CISCO-BUG-ID", value:"CSCei62762");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuk27655");
  script_xref(name:"CISCO-SR", value:"cisco-sr-20060906-gre");

  script_name(english:"Cisco IOS GRE Decapsulation Vulnerability");
  script_summary(english:"IOS Version Check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote device contains a flaw in the way GRE packets are handled. 
By sending a specially crafted GRE packet, an attacker can take
advantage of this flaw to potentially bypass access-control lists."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?89ca8c19");
  script_set_attribute(attribute:"see_also",value:"http://www.securityfocus.com/archive/1/445322/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sr-20060906-gre."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
 
  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/version");

  exit(0);
}

include("cisco_func.inc");
include("audit.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.1(0)PCHK1')
  security_note(0);
else if (version == '12.1(0)PCHK10')
  security_note(0);
else if (version == '12.1(0)PCHK11')
  security_note(0);
else if (version == '12.1(0)PCHK12')
  security_note(0);
else if (version == '12.1(0)PCHK13')
  security_note(0);
else if (version == '12.1(0)PCHK14')
  security_note(0);
else if (version == '12.1(0)PCHK15')
  security_note(0);
else if (version == '12.1(0)PCHK16')
  security_note(0);
else if (version == '12.1(0)PCHK17')
  security_note(0);
else if (version == '12.1(0)PCHK18')
  security_note(0);
else if (version == '12.1(0)PCHK19')
  security_note(0);
else if (version == '12.1(0)PCHK2')
  security_note(0);
else if (version == '12.1(0)PCHK20')
  security_note(0);
else if (version == '12.1(0)PCHK21')
  security_note(0);
else if (version == '12.1(0)PCHK22')
  security_note(0);
else if (version == '12.1(0)PCHK23')
  security_note(0);
else if (version == '12.1(0)PCHK24')
  security_note(0);
else if (version == '12.1(0)PCHK3')
  security_note(0);
else if (version == '12.1(0)PCHK4')
  security_note(0);
else if (version == '12.1(0)PCHK5')
  security_note(0);
else if (version == '12.1(0)PCHK6')
  security_note(0);
else if (version == '12.1(0)PCHK7')
  security_note(0);
else if (version == '12.1(0)PCHK8')
  security_note(0);
else if (version == '12.1(0)PCHK9')
  security_note(0);
else if (version == '12.1(0)PCHK92')
  security_note(0);
else if (version == '12.1(10)E')
  security_note(0);
else if (version == '12.1(10)E1')
  security_note(0);
else if (version == '12.1(10)E2')
  security_note(0);
else if (version == '12.1(10)E3')
  security_note(0);
else if (version == '12.1(10)E4')
  security_note(0);
else if (version == '12.1(10)E5')
  security_note(0);
else if (version == '12.1(10)E6')
  security_note(0);
else if (version == '12.1(10)E6a')
  security_note(0);
else if (version == '12.1(10)E7')
  security_note(0);
else if (version == '12.1(10)E8')
  security_note(0);
else if (version == '12.1(10)EC')
  security_note(0);
else if (version == '12.1(10)EC1')
  security_note(0);
else if (version == '12.1(10)EV')
  security_note(0);
else if (version == '12.1(10)EV1')
  security_note(0);
else if (version == '12.1(10)EV1a')
  security_note(0);
else if (version == '12.1(10)EV1b')
  security_note(0);
else if (version == '12.1(10)EV2')
  security_note(0);
else if (version == '12.1(10)EV3')
  security_note(0);
else if (version == '12.1(10)EV4')
  security_note(0);
else if (version == '12.1(10)EX')
  security_note(0);
else if (version == '12.1(10)EX1')
  security_note(0);
else if (version == '12.1(10)EX2')
  security_note(0);
else if (version == '12.1(10)EY')
  security_note(0);
else if (version == '12.1(10r)EV')
  security_note(0);
else if (version == '12.1(10r)EV1')
  security_note(0);
else if (version == '12.1(11a)EW')
  security_note(0);
else if (version == '12.1(11b)E')
  security_note(0);
else if (version == '12.1(11b)E0a')
  security_note(0);
else if (version == '12.1(11b)E1')
  security_note(0);
else if (version == '12.1(11b)E10')
  security_note(0);
else if (version == '12.1(11b)E11')
  security_note(0);
else if (version == '12.1(11b)E12')
  security_note(0);
else if (version == '12.1(11b)E13')
  security_note(0);
else if (version == '12.1(11b)E14')
  security_note(0);
else if (version == '12.1(11b)E2')
  security_note(0);
else if (version == '12.1(11b)E3')
  security_note(0);
else if (version == '12.1(11b)E4')
  security_note(0);
else if (version == '12.1(11b)E5')
  security_note(0);
else if (version == '12.1(11b)E6')
  security_note(0);
else if (version == '12.1(11b)E7')
  security_note(0);
else if (version == '12.1(11b)E8')
  security_note(0);
else if (version == '12.1(11b)E9')
  security_note(0);
else if (version == '12.1(11b)EC')
  security_note(0);
else if (version == '12.1(11b)EC1')
  security_note(0);
else if (version == '12.1(11b)EW')
  security_note(0);
else if (version == '12.1(11b)EW1')
  security_note(0);
else if (version == '12.1(11b)EX')
  security_note(0);
else if (version == '12.1(11b)EX1')
  security_note(0);
else if (version == '12.1(11)E')
  security_note(0);
else if (version == '12.1(11)EA1')
  security_note(0);
else if (version == '12.1(11)EA1a')
  security_note(0);
else if (version == '12.1(11e)CSFB')
  security_note(0);
else if (version == '12.1(11)EX')
  security_note(0);
else if (version == '12.1(11r)E')
  security_note(0);
else if (version == '12.1(11r)E1')
  security_note(0);
else if (version == '12.1(11r)E2')
  security_note(0);
else if (version == '12.1(11r)E3')
  security_note(0);
else if (version == '12.1(12c)E')
  security_note(0);
else if (version == '12.1(12c)E1')
  security_note(0);
else if (version == '12.1(12c)E2')
  security_note(0);
else if (version == '12.1(12c)E3')
  security_note(0);
else if (version == '12.1(12c)E4')
  security_note(0);
else if (version == '12.1(12c)E5')
  security_note(0);
else if (version == '12.1(12c)E6')
  security_note(0);
else if (version == '12.1(12c)E7')
  security_note(0);
else if (version == '12.1(12c)EA1')
  security_note(0);
else if (version == '12.1(12c)EA1a')
  security_note(0);
else if (version == '12.1(12c)EC')
  security_note(0);
else if (version == '12.1(12c)EC1')
  security_note(0);
else if (version == '12.1(12c)EV')
  security_note(0);
else if (version == '12.1(12c)EV1')
  security_note(0);
else if (version == '12.1(12c)EV2')
  security_note(0);
else if (version == '12.1(12c)EV3')
  security_note(0);
else if (version == '12.1(12c)EW')
  security_note(0);
else if (version == '12.1(12c)EW1')
  security_note(0);
else if (version == '12.1(12c)EW2')
  security_note(0);
else if (version == '12.1(12c)EW3')
  security_note(0);
else if (version == '12.1(12c)EW4')
  security_note(0);
else if (version == '12.1(12c)EX')
  security_note(0);
else if (version == '12.1(12c)EX1')
  security_note(0);
else if (version == '12.1(12c)EY')
  security_note(0);
else if (version == '12.1(12)E')
  security_note(0);
else if (version == '12.1(12e)TEST2')
  security_note(0);
else if (version == '12.1(12)EV')
  security_note(0);
else if (version == '12.1(12r)EX')
  security_note(0);
else if (version == '12.1(12r)EX1')
  security_note(0);
else if (version == '12.1(12r)EZ')
  security_note(0);
else if (version == '12.1(13)AY')
  security_note(0);
else if (version == '12.1(13)E')
  security_note(0);
else if (version == '12.1(13)E1')
  security_note(0);
else if (version == '12.1(13)E10')
  security_note(0);
else if (version == '12.1(13)E11')
  security_note(0);
else if (version == '12.1(13)E12')
  security_note(0);
else if (version == '12.1(13)E13')
  security_note(0);
else if (version == '12.1(13)E14')
  security_note(0);
else if (version == '12.1(13)E15')
  security_note(0);
else if (version == '12.1(13)E16')
  security_note(0);
else if (version == '12.1(13)E17')
  security_note(0);
else if (version == '12.1(13)E2')
  security_note(0);
else if (version == '12.1(13)E3')
  security_note(0);
else if (version == '12.1(13)E4')
  security_note(0);
else if (version == '12.1(13)E5')
  security_note(0);
else if (version == '12.1(13)E6')
  security_note(0);
else if (version == '12.1(13)E7')
  security_note(0);
else if (version == '12.1(13)E8')
  security_note(0);
else if (version == '12.1(13)E9')
  security_note(0);
else if (version == '12.1(13)EA1')
  security_note(0);
else if (version == '12.1(13)EA1a')
  security_note(0);
else if (version == '12.1(13)EA1b')
  security_note(0);
else if (version == '12.1(13)EA1c')
  security_note(0);
else if (version == '12.1(13)EB')
  security_note(0);
else if (version == '12.1(13)EB1')
  security_note(0);
else if (version == '12.1(13)EC')
  security_note(0);
else if (version == '12.1(13)EC1')
  security_note(0);
else if (version == '12.1(13)EC2')
  security_note(0);
else if (version == '12.1(13)EC3')
  security_note(0);
else if (version == '12.1(13)EC4')
  security_note(0);
else if (version == '12.1(13e)TEST041603')
  security_note(0);
else if (version == '12.1(13)EW')
  security_note(0);
else if (version == '12.1(13)EW1')
  security_note(0);
else if (version == '12.1(13)EW2')
  security_note(0);
else if (version == '12.1(13)EW3')
  security_note(0);
else if (version == '12.1(13)EW4')
  security_note(0);
else if (version == '12.1(13)EX')
  security_note(0);
else if (version == '12.1(13)EX1')
  security_note(0);
else if (version == '12.1(13)EX2')
  security_note(0);
else if (version == '12.1(13)EX3')
  security_note(0);
else if (version == '12.1(13r)E1')
  security_note(0);
else if (version == '12.1(14)AX')
  security_note(0);
else if (version == '12.1(14)AX1')
  security_note(0);
else if (version == '12.1(14)AX2')
  security_note(0);
else if (version == '12.1(14)AX3')
  security_note(0);
else if (version == '12.1(14)AX4')
  security_note(0);
else if (version == '12.1(14)AY1')
  security_note(0);
else if (version == '12.1(14)AY2')
  security_note(0);
else if (version == '12.1(14)AY3')
  security_note(0);
else if (version == '12.1(14)AY4')
  security_note(0);
else if (version == '12.1(14)AZ')
  security_note(0);
else if (version == '12.1(14)E')
  security_note(0);
else if (version == '12.1(14)E1')
  security_note(0);
else if (version == '12.1(14)E10')
  security_note(0);
else if (version == '12.1(14)E2')
  security_note(0);
else if (version == '12.1(14)E3')
  security_note(0);
else if (version == '12.1(14)E4')
  security_note(0);
else if (version == '12.1(14)E5')
  security_note(0);
else if (version == '12.1(14)E6')
  security_note(0);
else if (version == '12.1(14)E7')
  security_note(0);
else if (version == '12.1(14)E8')
  security_note(0);
else if (version == '12.1(14)E9')
  security_note(0);
else if (version == '12.1(14)EA1')
  security_note(0);
else if (version == '12.1(14)EA1a')
  security_note(0);
else if (version == '12.1(14)EA1b')
  security_note(0);
else if (version == '12.1(14)EB')
  security_note(0);
else if (version == '12.1(14)EB1')
  security_note(0);
else if (version == '12.1(14)EO')
  security_note(0);
else if (version == '12.1(14)EO1')
  security_note(0);
else if (version == '12.1(14r)EO')
  security_note(0);
else if (version == '12.1(14)SX')
  security_note(0);
else if (version == '12.1(14)SX')
  security_note(0);
else if (version == '12.1(19)E')
  security_note(0);
else if (version == '12.1(19)E1')
  security_note(0);
else if (version == '12.1(19)E1a')
  security_note(0);
else if (version == '12.1(19)E2')
  security_note(0);
else if (version == '12.1(19)E3')
  security_note(0);
else if (version == '12.1(19)E4')
  security_note(0);
else if (version == '12.1(19)E5')
  security_note(0);
else if (version == '12.1(19)E6')
  security_note(0);
else if (version == '12.1(19)E7')
  security_note(0);
else if (version == '12.1(19)EA1')
  security_note(0);
else if (version == '12.1(19)EA1a')
  security_note(0);
else if (version == '12.1(19)EA1b')
  security_note(0);
else if (version == '12.1(19)EA1c')
  security_note(0);
else if (version == '12.1(19)EA1d')
  security_note(0);
else if (version == '12.1(19)EB')
  security_note(0);
else if (version == '12.1(19)EC')
  security_note(0);
else if (version == '12.1(19)EC1')
  security_note(0);
else if (version == '12.1(19)EO')
  security_note(0);
else if (version == '12.1(19)EO1')
  security_note(0);
else if (version == '12.1(19)EO2')
  security_note(0);
else if (version == '12.1(19)EO3')
  security_note(0);
else if (version == '12.1(19)EO4')
  security_note(0);
else if (version == '12.1(19)EO5')
  security_note(0);
else if (version == '12.1(19)EW')
  security_note(0);
else if (version == '12.1(19)EW1')
  security_note(0);
else if (version == '12.1(19)EW2')
  security_note(0);
else if (version == '12.1(19)EW3')
  security_note(0);
else if (version == '12.1(1)EX')
  security_note(0);
else if (version == '12.1(1)EX1')
  security_note(0);
else if (version == '12.1(1)PE')
  security_note(0);
else if (version == '12.1(1r)EX')
  security_note(0);
else if (version == '12.1(20)E')
  security_note(0);
else if (version == '12.1(20)E1')
  security_note(0);
else if (version == '12.1(20)E2')
  security_note(0);
else if (version == '12.1(20)E3')
  security_note(0);
else if (version == '12.1(20)E4')
  security_note(0);
else if (version == '12.1(20)E5')
  security_note(0);
else if (version == '12.1(20)E6')
  security_note(0);
else if (version == '12.1(20)EA1')
  security_note(0);
else if (version == '12.1(20)EA1a')
  security_note(0);
else if (version == '12.1(20)EA1b')
  security_note(0);
else if (version == '12.1(20)EA2')
  security_note(0);
else if (version == '12.1(20)EB')
  security_note(0);
else if (version == '12.1(20)EC')
  security_note(0);
else if (version == '12.1(20)EC1')
  security_note(0);
else if (version == '12.1(20)EC2')
  security_note(0);
else if (version == '12.1(20)EC3')
  security_note(0);
else if (version == '12.1(20)EO')
  security_note(0);
else if (version == '12.1(20)EO1')
  security_note(0);
else if (version == '12.1(20)EO2')
  security_note(0);
else if (version == '12.1(20)EO3')
  security_note(0);
else if (version == '12.1(20)EU')
  security_note(0);
else if (version == '12.1(20)EU1')
  security_note(0);
else if (version == '12.1(20)EW')
  security_note(0);
else if (version == '12.1(20)EW1')
  security_note(0);
else if (version == '12.1(20)EW2')
  security_note(0);
else if (version == '12.1(20)EW3')
  security_note(0);
else if (version == '12.1(20)EW4')
  security_note(0);
else if (version == '12.1(22)AY')
  security_note(0);
else if (version == '12.1(22)AY1')
  security_note(0);
else if (version == '12.1(22)AY2')
  security_note(0);
else if (version == '12.1(22)E')
  security_note(0);
else if (version == '12.1(22)E1')
  security_note(0);
else if (version == '12.1(22)E2')
  security_note(0);
else if (version == '12.1(22)E3')
  security_note(0);
else if (version == '12.1(22)E4')
  security_note(0);
else if (version == '12.1(22)E5')
  security_note(0);
else if (version == '12.1(22)E6')
  security_note(0);
else if (version == '12.1(22)EA1')
  security_note(0);
else if (version == '12.1(22)EA10')
  security_note(0);
else if (version == '12.1(22)EA10a')
  security_note(0);
else if (version == '12.1(22)EA10b')
  security_note(0);
else if (version == '12.1(22)EA11')
  security_note(0);
else if (version == '12.1(22)EA12')
  security_note(0);
else if (version == '12.1(22)EA13')
  security_note(0);
else if (version == '12.1(22)EA14')
  security_note(0);
else if (version == '12.1(22)EA1a')
  security_note(0);
else if (version == '12.1(22)EA1b')
  security_note(0);
else if (version == '12.1(22)EA2')
  security_note(0);
else if (version == '12.1(22)EA3')
  security_note(0);
else if (version == '12.1(22)EA4')
  security_note(0);
else if (version == '12.1(22)EA4a')
  security_note(0);
else if (version == '12.1(22)EA5')
  security_note(0);
else if (version == '12.1(22)EA5a')
  security_note(0);
else if (version == '12.1(22)EA6')
  security_note(0);
else if (version == '12.1(22)EA6a')
  security_note(0);
else if (version == '12.1(22)EA7')
  security_note(0);
else if (version == '12.1(22)EA9')
  security_note(0);
else if (version == '12.1(22)EB')
  security_note(0);
else if (version == '12.1(22)EC')
  security_note(0);
else if (version == '12.1(22)EC1')
  security_note(0);
else if (version == '12.1(23)E')
  security_note(0);
else if (version == '12.1(23)E1')
  security_note(0);
else if (version == '12.1(23)E2')
  security_note(0);
else if (version == '12.1(23)E3')
  security_note(0);
else if (version == '12.1(23)E4')
  security_note(0);
else if (version == '12.1(23)EB')
  security_note(0);
else if (version == '12.1(26)E')
  security_note(0);
else if (version == '12.1(26)E1')
  security_note(0);
else if (version == '12.1(26)E2')
  security_note(0);
else if (version == '12.1(26)E3')
  security_note(0);
else if (version == '12.1(26)E4')
  security_note(0);
else if (version == '12.1(26)E5')
  security_note(0);
else if (version == '12.1(26)E6')
  security_note(0);
else if (version == '12.1(26)EB')
  security_note(0);
else if (version == '12.1(26)EB1')
  security_note(0);
else if (version == '12.1(26)EB2')
  security_note(0);
else if (version == '12.1(2)EC')
  security_note(0);
else if (version == '12.1(2)EC1')
  security_note(0);
else if (version == '12.1(3a)EC')
  security_note(0);
else if (version == '12.1(3a)EC1')
  security_note(0);
else if (version == '12.1(4)CX')
  security_note(0);
else if (version == '12.1(4)EC')
  security_note(0);
else if (version == '12.1(5c)EX')
  security_note(0);
else if (version == '12.1(5c)EX1')
  security_note(0);
else if (version == '12.1(5c)EX2')
  security_note(0);
else if (version == '12.1(5c)EX3')
  security_note(0);
else if (version == '12.1(5)EC')
  security_note(0);
else if (version == '12.1(5)EC1')
  security_note(0);
else if (version == '12.1(5)EX')
  security_note(0);
else if (version == '12.1(5)EY')
  security_note(0);
else if (version == '12.1(5)EY1')
  security_note(0);
else if (version == '12.1(5)EY2')
  security_note(0);
else if (version == '12.1(6)EA1')
  security_note(0);
else if (version == '12.1(6)EA1a')
  security_note(0);
else if (version == '12.1(6)EC')
  security_note(0);
else if (version == '12.1(6)EC1')
  security_note(0);
else if (version == '12.1(6e)PE1')
  security_note(0);
else if (version == '12.1(6)EX')
  security_note(0);
else if (version == '12.1(6)EY')
  security_note(0);
else if (version == '12.1(6)EY1')
  security_note(0);
else if (version == '12.1(6)EZ')
  security_note(0);
else if (version == '12.1(6)EZ1')
  security_note(0);
else if (version == '12.1(6)EZ2')
  security_note(0);
else if (version == '12.1(6)EZ3')
  security_note(0);
else if (version == '12.1(6)EZ4')
  security_note(0);
else if (version == '12.1(6)EZ5')
  security_note(0);
else if (version == '12.1(6)EZ6')
  security_note(0);
else if (version == '12.1(6)EZ7')
  security_note(0);
else if (version == '12.1(6)EZ8')
  security_note(0);
else if (version == '12.1(70)E')
  security_note(0);
else if (version == '12.1(70)E1')
  security_note(0);
else if (version == '12.1(70)E2')
  security_note(0);
else if (version == '12.1(7a)E1a')
  security_note(0);
else if (version == '12.1(7a)E2')
  security_note(0);
else if (version == '12.1(7a)E3')
  security_note(0);
else if (version == '12.1(7a)E4')
  security_note(0);
else if (version == '12.1(7a)E5')
  security_note(0);
else if (version == '12.1(7a)E6')
  security_note(0);
else if (version == '12.1(7a)EY')
  security_note(0);
else if (version == '12.1(7a)EY1')
  security_note(0);
else if (version == '12.1(7a)EY2')
  security_note(0);
else if (version == '12.1(7a)EY3')
  security_note(0);
else if (version == '12.1(7)CX')
  security_note(0);
else if (version == '12.1(7)CX1')
  security_note(0);
else if (version == '12.1(7)EC')
  security_note(0);
else if (version == '12.1(89)E1e')
  security_note(0);
else if (version == '12.1(8a)E')
  security_note(0);
else if (version == '12.1(8a)E1')
  security_note(0);
else if (version == '12.1(8a)E10102001')
  security_note(0);
else if (version == '12.1(8a)E2')
  security_note(0);
else if (version == '12.1(8a)E3')
  security_note(0);
else if (version == '12.1(8a)E4')
  security_note(0);
else if (version == '12.1(8a)E5')
  security_note(0);
else if (version == '12.1(8a)EW')
  security_note(0);
else if (version == '12.1(8a)EW1')
  security_note(0);
else if (version == '12.1(8a)EX')
  security_note(0);
else if (version == '12.1(8a)EX1')
  security_note(0);
else if (version == '12.1(8b)E10')
  security_note(0);
else if (version == '12.1(8b)E11')
  security_note(0);
else if (version == '12.1(8b)E12')
  security_note(0);
else if (version == '12.1(8b)E13')
  security_note(0);
else if (version == '12.1(8b)E14')
  security_note(0);
else if (version == '12.1(8b)E15')
  security_note(0);
else if (version == '12.1(8b)E16')
  security_note(0);
else if (version == '12.1(8b)E17')
  security_note(0);
else if (version == '12.1(8b)E18')
  security_note(0);
else if (version == '12.1(8b)E19')
  security_note(0);
else if (version == '12.1(8b)E20')
  security_note(0);
else if (version == '12.1(8b)E6')
  security_note(0);
else if (version == '12.1(8b)E7')
  security_note(0);
else if (version == '12.1(8b)E8')
  security_note(0);
else if (version == '12.1(8b)E9')
  security_note(0);
else if (version == '12.1(8b)EX2')
  security_note(0);
else if (version == '12.1(8b)EX3')
  security_note(0);
else if (version == '12.1(8b)EX4')
  security_note(0);
else if (version == '12.1(8b)EX5')
  security_note(0);
else if (version == '12.1(8)E')
  security_note(0);
else if (version == '12.1(8)EA1')
  security_note(0);
else if (version == '12.1(8)EA1b')
  security_note(0);
else if (version == '12.1(8)EA1c')
  security_note(0);
else if (version == '12.1(8)EC')
  security_note(0);
else if (version == '12.1(8)EC1')
  security_note(0);
else if (version == '12.1(8e)NAT001')
  security_note(0);
else if (version == '12.1(8)EX')
  security_note(0);
else if (version == '12.1(9)E')
  security_note(0);
else if (version == '12.1(9)E1')
  security_note(0);
else if (version == '12.1(9)E2')
  security_note(0);
else if (version == '12.1(9)E3')
  security_note(0);
else if (version == '12.1(9)EA1')
  security_note(0);
else if (version == '12.1(9)EA1a')
  security_note(0);
else if (version == '12.1(9)EA1c')
  security_note(0);
else if (version == '12.1(9)EA1d')
  security_note(0);
else if (version == '12.1(9)EC')
  security_note(0);
else if (version == '12.1(9)EC1')
  security_note(0);
else if (version == '12.1(9)EX')
  security_note(0);
else if (version == '12.1(9)EX1')
  security_note(0);
else if (version == '12.1(9)EX2')
  security_note(0);
else if (version == '12.1(9)EX3')
  security_note(0);
else if (version == '12.1(9r)EX')
  security_note(0);
else if (version == '12.2(1)')
  security_note(0);
else if (version == '12.2(10)')
  security_note(0);
else if (version == '12.2(10a)')
  security_note(0);
else if (version == '12.2(10b)')
  security_note(0);
else if (version == '12.2(10c)')
  security_note(0);
else if (version == '12.2(10d)')
  security_note(0);
else if (version == '12.2(10)DA')
  security_note(0);
else if (version == '12.2(10)DA1')
  security_note(0);
else if (version == '12.2(10)DA2')
  security_note(0);
else if (version == '12.2(10)DA3')
  security_note(0);
else if (version == '12.2(10)DA4')
  security_note(0);
else if (version == '12.2(10e)')
  security_note(0);
else if (version == '12.2(10f)')
  security_note(0);
else if (version == '12.2(10g)')
  security_note(0);
else if (version == '12.2(10)SBT112')
  security_note(0);
else if (version == '12.2(11)BC1')
  security_note(0);
else if (version == '12.2(11)BC1a')
  security_note(0);
else if (version == '12.2(11)BC1b')
  security_note(0);
else if (version == '12.2(11)BC2')
  security_note(0);
else if (version == '12.2(11)BC2a')
  security_note(0);
else if (version == '12.2(11)BC3')
  security_note(0);
else if (version == '12.2(11)BC3a')
  security_note(0);
else if (version == '12.2(11)BC3b')
  security_note(0);
else if (version == '12.2(11)BC3c')
  security_note(0);
else if (version == '12.2(11)BC3d')
  security_note(0);
else if (version == '12.2(11)CX')
  security_note(0);
else if (version == '12.2(11)CX1')
  security_note(0);
else if (version == '12.2(11)CY')
  security_note(0);
else if (version == '12.2(11)JA')
  security_note(0);
else if (version == '12.2(11)JA1')
  security_note(0);
else if (version == '12.2(11)JA2')
  security_note(0);
else if (version == '12.2(11)JA3')
  security_note(0);
else if (version == '12.2(11r)SZ')
  security_note(0);
else if (version == '12.2(11r)T')
  security_note(0);
else if (version == '12.2(11r)T1')
  security_note(0);
else if (version == '12.2(11r)YQ')
  security_note(0);
else if (version == '12.2(11r)YQ1')
  security_note(0);
else if (version == '12.2(11r)YQ2')
  security_note(0);
else if (version == '12.2(11r)YQ3')
  security_note(0);
else if (version == '12.2(11r)YQ4')
  security_note(0);
else if (version == '12.2(11r)YS1')
  security_note(0);
else if (version == '12.2(11r)YV')
  security_note(0);
else if (version == '12.2(11r)YV1')
  security_note(0);
else if (version == '12.2(11r)YV2')
  security_note(0);
else if (version == '12.2(11r)YV3')
  security_note(0);
else if (version == '12.2(11r)YV4')
  security_note(0);
else if (version == '12.2(11r)YV5')
  security_note(0);
else if (version == '12.2(11r)YV6')
  security_note(0);
else if (version == '12.2(11r)YZ')
  security_note(0);
else if (version == '12.2(11r)YZ1')
  security_note(0);
else if (version == '12.2(11r)YZ2')
  security_note(0);
else if (version == '12.2(11r)YZ3')
  security_note(0);
else if (version == '12.2(11)S')
  security_note(0);
else if (version == '12.2(11)S1')
  security_note(0);
else if (version == '12.2(11)S2')
  security_note(0);
else if (version == '12.2(11)S3')
  security_note(0);
else if (version == '12.2(11)SBT112')
  security_note(0);
else if (version == '12.2(11)T')
  security_note(0);
else if (version == '12.2(11)T1')
  security_note(0);
else if (version == '12.2(11)T10')
  security_note(0);
else if (version == '12.2(11)T11')
  security_note(0);
else if (version == '12.2(11)T2')
  security_note(0);
else if (version == '12.2(11)T3')
  security_note(0);
else if (version == '12.2(11)T4')
  security_note(0);
else if (version == '12.2(11)T5')
  security_note(0);
else if (version == '12.2(11)T6')
  security_note(0);
else if (version == '12.2(11)T7')
  security_note(0);
else if (version == '12.2(11)T8')
  security_note(0);
else if (version == '12.2(11)T9')
  security_note(0);
else if (version == '12.2(11)YP1')
  security_note(0);
else if (version == '12.2(11)YP2')
  security_note(0);
else if (version == '12.2(11)YP3')
  security_note(0);
else if (version == '12.2(11)YP4')
  security_note(0);
else if (version == '12.2(11)YP5')
  security_note(0);
else if (version == '12.2(11)YQ')
  security_note(0);
else if (version == '12.2(11)YR')
  security_note(0);
else if (version == '12.2(11)YS021223')
  security_note(0);
else if (version == '12.2(11)YT')
  security_note(0);
else if (version == '12.2(11)YT1')
  security_note(0);
else if (version == '12.2(11)YT2')
  security_note(0);
else if (version == '12.2(11)YU')
  security_note(0);
else if (version == '12.2(11)YV')
  security_note(0);
else if (version == '12.2(11)YV1')
  security_note(0);
else if (version == '12.2(11)YX')
  security_note(0);
else if (version == '12.2(11)YX1')
  security_note(0);
else if (version == '12.2(11)YZ')
  security_note(0);
else if (version == '12.2(11)YZ1')
  security_note(0);
else if (version == '12.2(11)YZ2')
  security_note(0);
else if (version == '12.2(11)YZ3')
  security_note(0);
else if (version == '12.2(11)ZC')
  security_note(0);
else if (version == '12.2(12)DA')
  security_note(0);
else if (version == '12.2(12)DA1')
  security_note(0);
else if (version == '12.2(12)DA2')
  security_note(0);
else if (version == '12.2(12)DA3')
  security_note(0);
else if (version == '12.2(12)DA4')
  security_note(0);
else if (version == '12.2(12)DA5')
  security_note(0);
else if (version == '12.2(12)DA6')
  security_note(0);
else if (version == '12.2(12)DA7')
  security_note(0);
else if (version == '12.2(12)DA8')
  security_note(0);
else if (version == '12.2(12)DA9')
  security_note(0);
else if (version == '12.2(12)SBT112')
  security_note(0);
else if (version == '12.2(13)JA')
  security_note(0);
else if (version == '12.2(13)JA1')
  security_note(0);
else if (version == '12.2(13)JA2')
  security_note(0);
else if (version == '12.2(13)JA3')
  security_note(0);
else if (version == '12.2(13)JA4')
  security_note(0);
else if (version == '12.2(13)T')
  security_note(0);
else if (version == '12.2(13)T1')
  security_note(0);
else if (version == '12.2(13)T10')
  security_note(0);
else if (version == '12.2(13)T11')
  security_note(0);
else if (version == '12.2(13)T12')
  security_note(0);
else if (version == '12.2(13)T13')
  security_note(0);
else if (version == '12.2(13)T14')
  security_note(0);
else if (version == '12.2(13)T15')
  security_note(0);
else if (version == '12.2(13)T16')
  security_note(0);
else if (version == '12.2(13)T17')
  security_note(0);
else if (version == '12.2(13)T1a')
  security_note(0);
else if (version == '12.2(13)T2')
  security_note(0);
else if (version == '12.2(13)T3')
  security_note(0);
else if (version == '12.2(13)T4')
  security_note(0);
else if (version == '12.2(13)T5')
  security_note(0);
else if (version == '12.2(13)T6')
  security_note(0);
else if (version == '12.2(13)T7')
  security_note(0);
else if (version == '12.2(13)T8')
  security_note(0);
else if (version == '12.2(13)T8a')
  security_note(0);
else if (version == '12.2(13)T9')
  security_note(0);
else if (version == '12.2(13)ZC')
  security_note(0);
else if (version == '12.2(13)ZD')
  security_note(0);
else if (version == '12.2(13)ZD1')
  security_note(0);
else if (version == '12.2(13)ZD2')
  security_note(0);
else if (version == '12.2(13)ZD3')
  security_note(0);
else if (version == '12.2(13)ZD4')
  security_note(0);
else if (version == '12.2(13)ZE')
  security_note(0);
else if (version == '12.2(13)ZF')
  security_note(0);
else if (version == '12.2(13)ZF1')
  security_note(0);
else if (version == '12.2(13)ZF2')
  security_note(0);
else if (version == '12.2(13)ZG')
  security_note(0);
else if (version == '12.2(13)ZH')
  security_note(0);
else if (version == '12.2(13)ZH1')
  security_note(0);
else if (version == '12.2(13)ZH10')
  security_note(0);
else if (version == '12.2(13)ZH2')
  security_note(0);
else if (version == '12.2(13)ZH3')
  security_note(0);
else if (version == '12.2(13)ZH4')
  security_note(0);
else if (version == '12.2(13)ZH5')
  security_note(0);
else if (version == '12.2(13)ZH6')
  security_note(0);
else if (version == '12.2(13)ZH7')
  security_note(0);
else if (version == '12.2(13)ZH8')
  security_note(0);
else if (version == '12.2(13)ZH9')
  security_note(0);
else if (version == '12.2(13)ZP')
  security_note(0);
else if (version == '12.2(13)ZP1')
  security_note(0);
else if (version == '12.2(13)ZP2')
  security_note(0);
else if (version == '12.2(13)ZP3')
  security_note(0);
else if (version == '12.2(13)ZP4')
  security_note(0);
else if (version == '12.2(13)ZT')
  security_note(0);
else if (version == '12.2(14r)S1')
  security_note(0);
else if (version == '12.2(14r)S1')
  security_note(0);
else if (version == '12.2(14r)S2')
  security_note(0);
else if (version == '12.2(14r)S2')
  security_note(0);
else if (version == '12.2(14r)S3')
  security_note(0);
else if (version == '12.2(14r)S3')
  security_note(0);
else if (version == '12.2(14r)S4')
  security_note(0);
else if (version == '12.2(14r)S4')
  security_note(0);
else if (version == '12.2(14r)S5')
  security_note(0);
else if (version == '12.2(14r)S6')
  security_note(0);
else if (version == '12.2(14r)S7')
  security_note(0);
else if (version == '12.2(14r)S8')
  security_note(0);
else if (version == '12.2(14r)S9')
  security_note(0);
else if (version == '12.2(14r)SZ')
  security_note(0);
else if (version == '12.2(14r)SZ1')
  security_note(0);
else if (version == '12.2(14)S')
  security_note(0);
else if (version == '12.2(14)S1')
  security_note(0);
else if (version == '12.2(14)S10')
  security_note(0);
else if (version == '12.2(14)S11')
  security_note(0);
else if (version == '12.2(14)S11a')
  security_note(0);
else if (version == '12.2(14)S11b')
  security_note(0);
else if (version == '12.2(14)S12')
  security_note(0);
else if (version == '12.2(14)S13')
  security_note(0);
else if (version == '12.2(14)S13a')
  security_note(0);
else if (version == '12.2(14)S13b')
  security_note(0);
else if (version == '12.2(14)S14')
  security_note(0);
else if (version == '12.2(14)S15')
  security_note(0);
else if (version == '12.2(14)S16')
  security_note(0);
else if (version == '12.2(14)S17')
  security_note(0);
else if (version == '12.2(14)S18')
  security_note(0);
else if (version == '12.2(14)S19')
  security_note(0);
else if (version == '12.2(14)S2')
  security_note(0);
else if (version == '12.2(14)S3')
  security_note(0);
else if (version == '12.2(14)S4')
  security_note(0);
else if (version == '12.2(14)S5')
  security_note(0);
else if (version == '12.2(14)S6')
  security_note(0);
else if (version == '12.2(14)S7')
  security_note(0);
else if (version == '12.2(14)S8')
  security_note(0);
else if (version == '12.2(14)S9')
  security_note(0);
else if (version == '12.2(14)S9a')
  security_note(0);
else if (version == '12.2(14)S9b')
  security_note(0);
else if (version == '12.2(14)S9c')
  security_note(0);
else if (version == '12.2(14)SU')
  security_note(0);
else if (version == '12.2(14)SU1')
  security_note(0);
else if (version == '12.2(14)SU2')
  security_note(0);
else if (version == '12.2(14)SX')
  security_note(0);
else if (version == '12.2(14)SX')
  security_note(0);
else if (version == '12.2(14)SX05282003')
  security_note(0);
else if (version == '12.2(14)SX05282003')
  security_note(0);
else if (version == '12.2(14)SX1')
  security_note(0);
else if (version == '12.2(14)SX1')
  security_note(0);
else if (version == '12.2(14)SX1a')
  security_note(0);
else if (version == '12.2(14)SX1a')
  security_note(0);
else if (version == '12.2(14)SX2')
  security_note(0);
else if (version == '12.2(14)SX2')
  security_note(0);
else if (version == '12.2(14)SY')
  security_note(0);
else if (version == '12.2(14)SY1')
  security_note(0);
else if (version == '12.2(14)SY2')
  security_note(0);
else if (version == '12.2(14)SY3')
  security_note(0);
else if (version == '12.2(14)SY4')
  security_note(0);
else if (version == '12.2(14)SY5')
  security_note(0);
else if (version == '12.2(14)SZ')
  security_note(0);
else if (version == '12.2(14)SZ1')
  security_note(0);
else if (version == '12.2(14)SZ2')
  security_note(0);
else if (version == '12.2(14)SZ3')
  security_note(0);
else if (version == '12.2(14)SZ4')
  security_note(0);
else if (version == '12.2(14)SZ5')
  security_note(0);
else if (version == '12.2(14)SZ6')
  security_note(0);
else if (version == '12.2(14)ZA')
  security_note(0);
else if (version == '12.2(14)ZA1')
  security_note(0);
else if (version == '12.2(14)ZA2')
  security_note(0);
else if (version == '12.2(14)ZA3')
  security_note(0);
else if (version == '12.2(14)ZA4')
  security_note(0);
else if (version == '12.2(14)ZA5')
  security_note(0);
else if (version == '12.2(14)ZA6')
  security_note(0);
else if (version == '12.2(14)ZA7')
  security_note(0);
else if (version == '12.2(15)B')
  security_note(0);
else if (version == '12.2(15)B1')
  security_note(0);
else if (version == '12.2(15)BC1')
  security_note(0);
else if (version == '12.2(15)BC1a')
  security_note(0);
else if (version == '12.2(15)BC1b')
  security_note(0);
else if (version == '12.2(15)BC1c')
  security_note(0);
else if (version == '12.2(15)BC1d')
  security_note(0);
else if (version == '12.2(15)BC1e')
  security_note(0);
else if (version == '12.2(15)BC1f')
  security_note(0);
else if (version == '12.2(15)BC1g')
  security_note(0);
else if (version == '12.2(15)BC2')
  security_note(0);
else if (version == '12.2(15)BC2a')
  security_note(0);
else if (version == '12.2(15)BC2b')
  security_note(0);
else if (version == '12.2(15)BC2c')
  security_note(0);
else if (version == '12.2(15)BC2d')
  security_note(0);
else if (version == '12.2(15)BC2e')
  security_note(0);
else if (version == '12.2(15)BC2f')
  security_note(0);
else if (version == '12.2(15)BC2g')
  security_note(0);
else if (version == '12.2(15)BC2h')
  security_note(0);
else if (version == '12.2(15)BC2i')
  security_note(0);
else if (version == '12.2(15)BX')
  security_note(0);
else if (version == '12.2(15)BZ')
  security_note(0);
else if (version == '12.2(15)BZ1')
  security_note(0);
else if (version == '12.2(15)BZ2')
  security_note(0);
else if (version == '12.2(15)CX')
  security_note(0);
else if (version == '12.2(15)CX1')
  security_note(0);
else if (version == '12.2(15)CZ')
  security_note(0);
else if (version == '12.2(15)CZ1')
  security_note(0);
else if (version == '12.2(15)CZ2')
  security_note(0);
else if (version == '12.2(15)CZ3')
  security_note(0);
else if (version == '12.2(15)JA')
  security_note(0);
else if (version == '12.2(15)JK')
  security_note(0);
else if (version == '12.2(15)JK1')
  security_note(0);
else if (version == '12.2(15)JK2')
  security_note(0);
else if (version == '12.2(15)JK3')
  security_note(0);
else if (version == '12.2(15)JK4')
  security_note(0);
else if (version == '12.2(15)JK5')
  security_note(0);
else if (version == '12.2(15l)JK')
  security_note(0);
else if (version == '12.2(15)MC1')
  security_note(0);
else if (version == '12.2(15)MC1a')
  security_note(0);
else if (version == '12.2(15)MC1b')
  security_note(0);
else if (version == '12.2(15)MC1c')
  security_note(0);
else if (version == '12.2(15)MC2')
  security_note(0);
else if (version == '12.2(15)MC2a')
  security_note(0);
else if (version == '12.2(15)MC2b')
  security_note(0);
else if (version == '12.2(15)MC2c')
  security_note(0);
else if (version == '12.2(15)MC2e')
  security_note(0);
else if (version == '12.2(15)MC2f')
  security_note(0);
else if (version == '12.2(15)MC2g')
  security_note(0);
else if (version == '12.2(15)MC2i')
  security_note(0);
else if (version == '12.2(15)MC2j')
  security_note(0);
else if (version == '12.2(15)MC2k')
  security_note(0);
else if (version == '12.2(15)MC2l')
  security_note(0);
else if (version == '12.2(15r)ZJ')
  security_note(0);
else if (version == '12.2(15)T')
  security_note(0);
else if (version == '12.2(15)T1')
  security_note(0);
else if (version == '12.2(15)T10')
  security_note(0);
else if (version == '12.2(15)T11')
  security_note(0);
else if (version == '12.2(15)T12')
  security_note(0);
else if (version == '12.2(15)T12a')
  security_note(0);
else if (version == '12.2(15)T13')
  security_note(0);
else if (version == '12.2(15)T14')
  security_note(0);
else if (version == '12.2(15)T15')
  security_note(0);
else if (version == '12.2(15)T16')
  security_note(0);
else if (version == '12.2(15)T17')
  security_note(0);
else if (version == '12.2(15)T1a')
  security_note(0);
else if (version == '12.2(15)T2')
  security_note(0);
else if (version == '12.2(15)T3')
  security_note(0);
else if (version == '12.2(15)T4')
  security_note(0);
else if (version == '12.2(15)T4a')
  security_note(0);
else if (version == '12.2(15)T4b')
  security_note(0);
else if (version == '12.2(15)T4c')
  security_note(0);
else if (version == '12.2(15)T4d')
  security_note(0);
else if (version == '12.2(15)T4e')
  security_note(0);
else if (version == '12.2(15)T5')
  security_note(0);
else if (version == '12.2(15)T5a')
  security_note(0);
else if (version == '12.2(15)T6')
  security_note(0);
else if (version == '12.2(15)T7')
  security_note(0);
else if (version == '12.2(15)T8')
  security_note(0);
else if (version == '12.2(15)T9')
  security_note(0);
else if (version == '12.2(15)T9a')
  security_note(0);
else if (version == '12.2(15)T9b')
  security_note(0);
else if (version == '12.2(15)XR')
  security_note(0);
else if (version == '12.2(15)XR1')
  security_note(0);
else if (version == '12.2(15)XR2')
  security_note(0);
else if (version == '12.2(15)YS030506')
  security_note(0);
else if (version == '12.2(15)ZJ')
  security_note(0);
else if (version == '12.2(15)ZJ1')
  security_note(0);
else if (version == '12.2(15)ZJ2')
  security_note(0);
else if (version == '12.2(15)ZJ3')
  security_note(0);
else if (version == '12.2(15)ZJ4')
  security_note(0);
else if (version == '12.2(15)ZJ5')
  security_note(0);
else if (version == '12.2(15)ZK')
  security_note(0);
else if (version == '12.2(15)ZK052803')
  security_note(0);
else if (version == '12.2(15)ZK061003')
  security_note(0);
else if (version == '12.2(15)ZK1')
  security_note(0);
else if (version == '12.2(15)ZK2')
  security_note(0);
else if (version == '12.2(15)ZK3')
  security_note(0);
else if (version == '12.2(15)ZK4')
  security_note(0);
else if (version == '12.2(15)ZK5')
  security_note(0);
else if (version == '12.2(15)ZK6')
  security_note(0);
else if (version == '12.2(15)ZL')
  security_note(0);
else if (version == '12.2(15)ZL1')
  security_note(0);
else if (version == '12.2(15)ZN')
  security_note(0);
else if (version == '12.2(15)ZO')
  security_note(0);
else if (version == '12.2(15)ZR')
  security_note(0);
else if (version == '12.2(15)ZS')
  security_note(0);
else if (version == '12.2(15)ZS1')
  security_note(0);
else if (version == '12.2(15)ZS2')
  security_note(0);
else if (version == '12.2(15)ZS3')
  security_note(0);
else if (version == '12.2(15)ZS4')
  security_note(0);
else if (version == '12.2(15)ZS5')
  security_note(0);
else if (version == '12.2(16)B')
  security_note(0);
else if (version == '12.2(16)B1')
  security_note(0);
else if (version == '12.2(16)B2')
  security_note(0);
else if (version == '12.2(16)B3')
  security_note(0);
else if (version == '12.2(16b)REG1')
  security_note(0);
else if (version == '12.2(16)BX')
  security_note(0);
else if (version == '12.2(16)BX1')
  security_note(0);
else if (version == '12.2(16)BX2')
  security_note(0);
else if (version == '12.2(16)BX3')
  security_note(0);
else if (version == '12.2(17a)SX')
  security_note(0);
else if (version == '12.2(17a)SX1')
  security_note(0);
else if (version == '12.2(17a)SX2')
  security_note(0);
else if (version == '12.2(17a)SX3')
  security_note(0);
else if (version == '12.2(17a)SX4')
  security_note(0);
else if (version == '12.2(17b)SXA')
  security_note(0);
else if (version == '12.2(17b)SXA1')
  security_note(0);
else if (version == '12.2(17b)SXA2')
  security_note(0);
else if (version == '12.2(17d)SXB')
  security_note(0);
else if (version == '12.2(17d)SXB1')
  security_note(0);
else if (version == '12.2(17d)SXB10')
  security_note(0);
else if (version == '12.2(17d)SXB11')
  security_note(0);
else if (version == '12.2(17d)SXB11a')
  security_note(0);
else if (version == '12.2(17d)SXB2')
  security_note(0);
else if (version == '12.2(17d)SXB3')
  security_note(0);
else if (version == '12.2(17d)SXB4')
  security_note(0);
else if (version == '12.2(17d)SXB5')
  security_note(0);
else if (version == '12.2(17d)SXB6')
  security_note(0);
else if (version == '12.2(17d)SXB7')
  security_note(0);
else if (version == '12.2(17d)SXB8')
  security_note(0);
else if (version == '12.2(17d)SXB9')
  security_note(0);
else if (version == '12.2(17r)S1')
  security_note(0);
else if (version == '12.2(17r)S2')
  security_note(0);
else if (version == '12.2(17r)S4')
  security_note(0);
else if (version == '12.2(17r)S5')
  security_note(0);
else if (version == '12.2(17r)S6')
  security_note(0);
else if (version == '12.2(17r)SX')
  security_note(0);
else if (version == '12.2(17r)SX1')
  security_note(0);
else if (version == '12.2(17r)SX2')
  security_note(0);
else if (version == '12.2(17r)SX3')
  security_note(0);
else if (version == '12.2(17r)SX5')
  security_note(0);
else if (version == '12.2(17r)SX6')
  security_note(0);
else if (version == '12.2(17r)SX7')
  security_note(0);
else if (version == '12.2(17r)SXB3')
  security_note(0);
else if (version == '12.2(18)IXA')
  security_note(0);
else if (version == '12.2(18)IXB')
  security_note(0);
else if (version == '12.2(18)IXB1')
  security_note(0);
else if (version == '12.2(18)IXB2')
  security_note(0);
else if (version == '12.2(18)IXC')
  security_note(0);
else if (version == '12.2(18)IXD')
  security_note(0);
else if (version == '12.2(18)IXD1')
  security_note(0);
else if (version == '12.2(18)IXE')
  security_note(0);
else if (version == '12.2(18)IXF')
  security_note(0);
else if (version == '12.2(18)IXF1')
  security_note(0);
else if (version == '12.2(18)IXG')
  security_note(0);
else if (version == '12.2(18)IXH')
  security_note(0);
else if (version == '12.2(18)IXH1')
  security_note(0);
else if (version == '12.2(18r)S3')
  security_note(0);
else if (version == '12.2(18r)SX1')
  security_note(0);
else if (version == '12.2(18r)SX2')
  security_note(0);
else if (version == '12.2(18r)SX3')
  security_note(0);
else if (version == '12.2(18r)SX4')
  security_note(0);
else if (version == '12.2(18r)SX5')
  security_note(0);
else if (version == '12.2(18r)SX7')
  security_note(0);
else if (version == '12.2(18r)SX8')
  security_note(0);
else if (version == '12.2(18r)SX9')
  security_note(0);
else if (version == '12.2(18)SXD')
  security_note(0);
else if (version == '12.2(18)SXD1')
  security_note(0);
else if (version == '12.2(18)SXD2')
  security_note(0);
else if (version == '12.2(18)SXD3')
  security_note(0);
else if (version == '12.2(18)SXD4')
  security_note(0);
else if (version == '12.2(18)SXD5')
  security_note(0);
else if (version == '12.2(18)SXD6')
  security_note(0);
else if (version == '12.2(18)SXD7')
  security_note(0);
else if (version == '12.2(18)SXD7a')
  security_note(0);
else if (version == '12.2(18)SXD7b')
  security_note(0);
else if (version == '12.2(18)SXE')
  security_note(0);
else if (version == '12.2(18)SXE1')
  security_note(0);
else if (version == '12.2(18)SXE2')
  security_note(0);
else if (version == '12.2(18)SXE3')
  security_note(0);
else if (version == '12.2(18)SXE4')
  security_note(0);
else if (version == '12.2(18)SXE5')
  security_note(0);
else if (version == '12.2(18)SXE6')
  security_note(0);
else if (version == '12.2(18)SXE6a')
  security_note(0);
else if (version == '12.2(18)SXE6b')
  security_note(0);
else if (version == '12.2(18)SXF')
  security_note(0);
else if (version == '12.2(18)SXF1')
  security_note(0);
else if (version == '12.2(18)SXF10')
  security_note(0);
else if (version == '12.2(18)SXF10a')
  security_note(0);
else if (version == '12.2(18)SXF11')
  security_note(0);
else if (version == '12.2(18)SXF12')
  security_note(0);
else if (version == '12.2(18)SXF12a')
  security_note(0);
else if (version == '12.2(18)SXF13')
  security_note(0);
else if (version == '12.2(18)SXF13a')
  security_note(0);
else if (version == '12.2(18)SXF13b')
  security_note(0);
else if (version == '12.2(18)SXF14')
  security_note(0);
else if (version == '12.2(18)SXF15')
  security_note(0);
else if (version == '12.2(18)SXF15a')
  security_note(0);
else if (version == '12.2(18)SXF16')
  security_note(0);
else if (version == '12.2(18)SXF17')
  security_note(0);
else if (version == '12.2(18)SXF17a')
  security_note(0);
else if (version == '12.2(18)SXF2')
  security_note(0);
else if (version == '12.2(18)SXF3')
  security_note(0);
else if (version == '12.2(18)SXF4')
  security_note(0);
else if (version == '12.2(18)SXF5')
  security_note(0);
else if (version == '12.2(18)SXF6')
  security_note(0);
else if (version == '12.2(18)SXF7')
  security_note(0);
else if (version == '12.2(18)SXF8')
  security_note(0);
else if (version == '12.2(18)SXF9')
  security_note(0);
else if (version == '12.2(18)ZU')
  security_note(0);
else if (version == '12.2(18)ZU1')
  security_note(0);
else if (version == '12.2(18)ZU2')
  security_note(0);
else if (version == '12.2(18)ZY')
  security_note(0);
else if (version == '12.2(18)ZY1')
  security_note(0);
else if (version == '12.2(18)ZY2')
  security_note(0);
else if (version == '12.2(18)ZYA')
  security_note(0);
else if (version == '12.2(18)ZYA1')
  security_note(0);
else if (version == '12.2(18)ZYA2')
  security_note(0);
else if (version == '12.2(18)ZYA3')
  security_note(0);
else if (version == '12.2(18)ZYA3a')
  security_note(0);
else if (version == '12.2(18)ZYA3b')
  security_note(0);
else if (version == '12.2(1a)')
  security_note(0);
else if (version == '12.2(1a)XC')
  security_note(0);
else if (version == '12.2(1a)XC1')
  security_note(0);
else if (version == '12.2(1a)XC2')
  security_note(0);
else if (version == '12.2(1a)XC3')
  security_note(0);
else if (version == '12.2(1a)XC4')
  security_note(0);
else if (version == '12.2(1a)XC5')
  security_note(0);
else if (version == '12.2(1b)')
  security_note(0);
else if (version == '12.2(1b)DA')
  security_note(0);
else if (version == '12.2(1b)DA1')
  security_note(0);
else if (version == '12.2(1c)')
  security_note(0);
else if (version == '12.2(1d)')
  security_note(0);
else if (version == '12.2(1)DX')
  security_note(0);
else if (version == '12.2(1)DX')
  security_note(0);
else if (version == '12.2(1)DX1')
  security_note(0);
else if (version == '12.2(1)DX1')
  security_note(0);
else if (version == '12.2(1)MB1')
  security_note(0);
else if (version == '12.2(1)MB1')
  security_note(0);
else if (version == '12.2(1r)')
  security_note(0);
else if (version == '12.2(1r)DD')
  security_note(0);
else if (version == '12.2(1r)DD')
  security_note(0);
else if (version == '12.2(1r)DD1')
  security_note(0);
else if (version == '12.2(1r)DD1')
  security_note(0);
else if (version == '12.2(1r)T')
  security_note(0);
else if (version == '12.2(1r)T')
  security_note(0);
else if (version == '12.2(1r)T1')
  security_note(0);
else if (version == '12.2(1r)T1')
  security_note(0);
else if (version == '12.2(1r)T2')
  security_note(0);
else if (version == '12.2(1r)XA')
  security_note(0);
else if (version == '12.2(1r)XA')
  security_note(0);
else if (version == '12.2(1r)XE')
  security_note(0);
else if (version == '12.2(1r)XE')
  security_note(0);
else if (version == '12.2(1r)XE1')
  security_note(0);
else if (version == '12.2(1r)XE1')
  security_note(0);
else if (version == '12.2(1r)XE2')
  security_note(0);
else if (version == '12.2(1r)XE2')
  security_note(0);
else if (version == '12.2(1)SBT112')
  security_note(0);
else if (version == '12.2(1)XD')
  security_note(0);
else if (version == '12.2(1)XD')
  security_note(0);
else if (version == '12.2(1)XD1')
  security_note(0);
else if (version == '12.2(1)XD1')
  security_note(0);
else if (version == '12.2(1)XD2')
  security_note(0);
else if (version == '12.2(1)XD2')
  security_note(0);
else if (version == '12.2(1)XD3')
  security_note(0);
else if (version == '12.2(1)XD3')
  security_note(0);
else if (version == '12.2(1)XD4')
  security_note(0);
else if (version == '12.2(1)XD4')
  security_note(0);
else if (version == '12.2(1)XE')
  security_note(0);
else if (version == '12.2(1)XE')
  security_note(0);
else if (version == '12.2(1)XE1')
  security_note(0);
else if (version == '12.2(1)XE1')
  security_note(0);
else if (version == '12.2(1)XE2')
  security_note(0);
else if (version == '12.2(1)XE2')
  security_note(0);
else if (version == '12.2(1)XS')
  security_note(0);
else if (version == '12.2(1)XS1')
  security_note(0);
else if (version == '12.2(1)XS1a')
  security_note(0);
else if (version == '12.2(1)XS2')
  security_note(0);
else if (version == '12.2(2)BX')
  security_note(0);
else if (version == '12.2(2)BX')
  security_note(0);
else if (version == '12.2(2)BX1')
  security_note(0);
else if (version == '12.2(2)BX1')
  security_note(0);
else if (version == '12.2(2)BX2')
  security_note(0);
else if (version == '12.2(2)BX2')
  security_note(0);
else if (version == '12.2(2)DD')
  security_note(0);
else if (version == '12.2(2)DD')
  security_note(0);
else if (version == '12.2(2)DD1')
  security_note(0);
else if (version == '12.2(2)DD1')
  security_note(0);
else if (version == '12.2(2)DD2')
  security_note(0);
else if (version == '12.2(2)DD2')
  security_note(0);
else if (version == '12.2(2)DD3')
  security_note(0);
else if (version == '12.2(2)DD3')
  security_note(0);
else if (version == '12.2(2)DD4')
  security_note(0);
else if (version == '12.2(2)DD4')
  security_note(0);
else if (version == '12.2(2)DX')
  security_note(0);
else if (version == '12.2(2)DX')
  security_note(0);
else if (version == '12.2(2)DX1')
  security_note(0);
else if (version == '12.2(2)DX1')
  security_note(0);
else if (version == '12.2(2)DX2')
  security_note(0);
else if (version == '12.2(2)DX2')
  security_note(0);
else if (version == '12.2(2)DX3')
  security_note(0);
else if (version == '12.2(2)DX3')
  security_note(0);
else if (version == '12.2(2r)')
  security_note(0);
else if (version == '12.2(2r)B9')
  security_note(0);
else if (version == '12.2(2r)DD')
  security_note(0);
else if (version == '12.2(2r)DD')
  security_note(0);
else if (version == '12.2(2r)T2')
  security_note(0);
else if (version == '12.2(2r)T2')
  security_note(0);
else if (version == '12.2(2r)XA')
  security_note(0);
else if (version == '12.2(2r)XA')
  security_note(0);
else if (version == '12.2(2r)XB')
  security_note(0);
else if (version == '12.2(2r)XB')
  security_note(0);
else if (version == '12.2(2r)XB5')
  security_note(0);
else if (version == '12.2(2r)XB5')
  security_note(0);
else if (version == '12.2(2r)XT')
  security_note(0);
else if (version == '12.2(2r)XT')
  security_note(0);
else if (version == '12.2(2)SBT112')
  security_note(0);
else if (version == '12.2(2)T')
  security_note(0);
else if (version == '12.2(2)T')
  security_note(0);
else if (version == '12.2(2)T1')
  security_note(0);
else if (version == '12.2(2)T1')
  security_note(0);
else if (version == '12.2(2)T2')
  security_note(0);
else if (version == '12.2(2)T2')
  security_note(0);
else if (version == '12.2(2)T3')
  security_note(0);
else if (version == '12.2(2)T3')
  security_note(0);
else if (version == '12.2(2)T4')
  security_note(0);
else if (version == '12.2(2)T4')
  security_note(0);
else if (version == '12.2(2)XA')
  security_note(0);
else if (version == '12.2(2)XA')
  security_note(0);
else if (version == '12.2(2)XA1')
  security_note(0);
else if (version == '12.2(2)XA1')
  security_note(0);
else if (version == '12.2(2)XA2')
  security_note(0);
else if (version == '12.2(2)XA2')
  security_note(0);
else if (version == '12.2(2)XA3')
  security_note(0);
else if (version == '12.2(2)XA3')
  security_note(0);
else if (version == '12.2(2)XA4')
  security_note(0);
else if (version == '12.2(2)XA4')
  security_note(0);
else if (version == '12.2(2)XA5')
  security_note(0);
else if (version == '12.2(2)XA5')
  security_note(0);
else if (version == '12.2(2)XB')
  security_note(0);
else if (version == '12.2(2)XB')
  security_note(0);
else if (version == '12.2(2)XB1')
  security_note(0);
else if (version == '12.2(2)XB1')
  security_note(0);
else if (version == '12.2(2)XB10')
  security_note(0);
else if (version == '12.2(2)XB10')
  security_note(0);
else if (version == '12.2(2)XB11')
  security_note(0);
else if (version == '12.2(2)XB11')
  security_note(0);
else if (version == '12.2(2)XB12')
  security_note(0);
else if (version == '12.2(2)XB12')
  security_note(0);
else if (version == '12.2(2)XB14')
  security_note(0);
else if (version == '12.2(2)XB14')
  security_note(0);
else if (version == '12.2(2)XB15')
  security_note(0);
else if (version == '12.2(2)XB15')
  security_note(0);
else if (version == '12.2(2)XB16')
  security_note(0);
else if (version == '12.2(2)XB16')
  security_note(0);
else if (version == '12.2(2)XB17')
  security_note(0);
else if (version == '12.2(2)XB17')
  security_note(0);
else if (version == '12.2(2)XB18')
  security_note(0);
else if (version == '12.2(2)XB18')
  security_note(0);
else if (version == '12.2(2)XB2')
  security_note(0);
else if (version == '12.2(2)XB2')
  security_note(0);
else if (version == '12.2(2)XB3')
  security_note(0);
else if (version == '12.2(2)XB3')
  security_note(0);
else if (version == '12.2(2)XB4')
  security_note(0);
else if (version == '12.2(2)XB4')
  security_note(0);
else if (version == '12.2(2)XB4b')
  security_note(0);
else if (version == '12.2(2)XB4b')
  security_note(0);
else if (version == '12.2(2)XB5')
  security_note(0);
else if (version == '12.2(2)XB5')
  security_note(0);
else if (version == '12.2(2)XB6')
  security_note(0);
else if (version == '12.2(2)XB6')
  security_note(0);
else if (version == '12.2(2)XB6a')
  security_note(0);
else if (version == '12.2(2)XB6a')
  security_note(0);
else if (version == '12.2(2)XB6b')
  security_note(0);
else if (version == '12.2(2)XB6b')
  security_note(0);
else if (version == '12.2(2)XB6c')
  security_note(0);
else if (version == '12.2(2)XB6c')
  security_note(0);
else if (version == '12.2(2)XB6d')
  security_note(0);
else if (version == '12.2(2)XB6d')
  security_note(0);
else if (version == '12.2(2)XB7')
  security_note(0);
else if (version == '12.2(2)XB7')
  security_note(0);
else if (version == '12.2(2)XB8')
  security_note(0);
else if (version == '12.2(2)XB8')
  security_note(0);
else if (version == '12.2(2)XB9')
  security_note(0);
else if (version == '12.2(2)XB9')
  security_note(0);
else if (version == '12.2(2)XC')
  security_note(0);
else if (version == '12.2(2)XC')
  security_note(0);
else if (version == '12.2(2)XC1')
  security_note(0);
else if (version == '12.2(2)XC1')
  security_note(0);
else if (version == '12.2(2)XC2')
  security_note(0);
else if (version == '12.2(2)XC2')
  security_note(0);
else if (version == '12.2(2)XC3')
  security_note(0);
else if (version == '12.2(2)XC3')
  security_note(0);
else if (version == '12.2(2)XC4')
  security_note(0);
else if (version == '12.2(2)XC4')
  security_note(0);
else if (version == '12.2(2)XC5')
  security_note(0);
else if (version == '12.2(2)XC5')
  security_note(0);
else if (version == '12.2(2)XC6')
  security_note(0);
else if (version == '12.2(2)XC6')
  security_note(0);
else if (version == '12.2(2)XC7')
  security_note(0);
else if (version == '12.2(2)XC7')
  security_note(0);
else if (version == '12.2(2)XF')
  security_note(0);
else if (version == '12.2(2)XF')
  security_note(0);
else if (version == '12.2(2)XF1')
  security_note(0);
else if (version == '12.2(2)XF1')
  security_note(0);
else if (version == '12.2(2)XF2')
  security_note(0);
else if (version == '12.2(2)XF2')
  security_note(0);
else if (version == '12.2(2)XG')
  security_note(0);
else if (version == '12.2(2)XG')
  security_note(0);
else if (version == '12.2(2)XG1')
  security_note(0);
else if (version == '12.2(2)XG1')
  security_note(0);
else if (version == '12.2(2)XH')
  security_note(0);
else if (version == '12.2(2)XH')
  security_note(0);
else if (version == '12.2(2)XH1')
  security_note(0);
else if (version == '12.2(2)XH1')
  security_note(0);
else if (version == '12.2(2)XH2')
  security_note(0);
else if (version == '12.2(2)XH2')
  security_note(0);
else if (version == '12.2(2)XI')
  security_note(0);
else if (version == '12.2(2)XI')
  security_note(0);
else if (version == '12.2(2)XI1')
  security_note(0);
else if (version == '12.2(2)XI1')
  security_note(0);
else if (version == '12.2(2)XI2')
  security_note(0);
else if (version == '12.2(2)XI2')
  security_note(0);
else if (version == '12.2(2)XJ')
  security_note(0);
else if (version == '12.2(2)XJ')
  security_note(0);
else if (version == '12.2(2)XK')
  security_note(0);
else if (version == '12.2(2)XK')
  security_note(0);
else if (version == '12.2(2)XK1')
  security_note(0);
else if (version == '12.2(2)XK1')
  security_note(0);
else if (version == '12.2(2)XK2')
  security_note(0);
else if (version == '12.2(2)XK2')
  security_note(0);
else if (version == '12.2(2)XK3')
  security_note(0);
else if (version == '12.2(2)XK3')
  security_note(0);
else if (version == '12.2(2)XN')
  security_note(0);
else if (version == '12.2(2)XN')
  security_note(0);
else if (version == '12.2(2)XQ')
  security_note(0);
else if (version == '12.2(2)XQ')
  security_note(0);
else if (version == '12.2(2)XQ1')
  security_note(0);
else if (version == '12.2(2)XQ1')
  security_note(0);
else if (version == '12.2(2)XR')
  security_note(0);
else if (version == '12.2(2)XR')
  security_note(0);
else if (version == '12.2(2)XT')
  security_note(0);
else if (version == '12.2(2)XT')
  security_note(0);
else if (version == '12.2(2)XT1')
  security_note(0);
else if (version == '12.2(2)XT1')
  security_note(0);
else if (version == '12.2(2)XT2')
  security_note(0);
else if (version == '12.2(2)XT2')
  security_note(0);
else if (version == '12.2(2)XT3')
  security_note(0);
else if (version == '12.2(2)XT3')
  security_note(0);
else if (version == '12.2(2)XU')
  security_note(0);
else if (version == '12.2(2)XU')
  security_note(0);
else if (version == '12.2(2)XU1')
  security_note(0);
else if (version == '12.2(2)XU1')
  security_note(0);
else if (version == '12.2(2)XU2')
  security_note(0);
else if (version == '12.2(2)XU2')
  security_note(0);
else if (version == '12.2(2)XU3')
  security_note(0);
else if (version == '12.2(2)XU3')
  security_note(0);
else if (version == '12.2(2)XU4')
  security_note(0);
else if (version == '12.2(2)XU4')
  security_note(0);
else if (version == '12.2(2)YC')
  security_note(0);
else if (version == '12.2(2)YC')
  security_note(0);
else if (version == '12.2(2)YC1')
  security_note(0);
else if (version == '12.2(2)YC1')
  security_note(0);
else if (version == '12.2(2)YC2')
  security_note(0);
else if (version == '12.2(2)YC2')
  security_note(0);
else if (version == '12.2(2)YC3')
  security_note(0);
else if (version == '12.2(2)YC3')
  security_note(0);
else if (version == '12.2(2)YC4')
  security_note(0);
else if (version == '12.2(2)YC4')
  security_note(0);
else if (version == '12.2(2)YK')
  security_note(0);
else if (version == '12.2(2)YK')
  security_note(0);
else if (version == '12.2(2)YK1')
  security_note(0);
else if (version == '12.2(2)YK1')
  security_note(0);
else if (version == '12.2(3)')
  security_note(0);
else if (version == '12.2(31a)XN2')
  security_note(0);
else if (version == '12.2(31a)XN3')
  security_note(0);
else if (version == '12.2(31b)XN2')
  security_note(0);
else if (version == '12.2(31b)XN3')
  security_note(0);
else if (version == '12.2(31c)XN2')
  security_note(0);
else if (version == '12.2(31c)XN3')
  security_note(0);
else if (version == '12.2(31r)SB')
  security_note(0);
else if (version == '12.2(31r)SB1')
  security_note(0);
else if (version == '12.2(31r)SB2')
  security_note(0);
else if (version == '12.2(31r)SB9a')
  security_note(0);
else if (version == '12.2(31)SB')
  security_note(0);
else if (version == '12.2(31)SB1')
  security_note(0);
else if (version == '12.2(31)SB10')
  security_note(0);
else if (version == '12.2(31)SB10a')
  security_note(0);
else if (version == '12.2(31)SB10b')
  security_note(0);
else if (version == '12.2(31)SB10c')
  security_note(0);
else if (version == '12.2(31)SB10d')
  security_note(0);
else if (version == '12.2(31)SB10e')
  security_note(0);
else if (version == '12.2(31)SB11')
  security_note(0);
else if (version == '12.2(31)SB11a')
  security_note(0);
else if (version == '12.2(31)SB11b')
  security_note(0);
else if (version == '12.2(31)SB12')
  security_note(0);
else if (version == '12.2(31)SB12a')
  security_note(0);
else if (version == '12.2(31)SB13')
  security_note(0);
else if (version == '12.2(31)SB13d')
  security_note(0);
else if (version == '12.2(31)SB13f')
  security_note(0);
else if (version == '12.2(31)SB13g')
  security_note(0);
else if (version == '12.2(31)SB14')
  security_note(0);
else if (version == '12.2(31)SB15')
  security_note(0);
else if (version == '12.2(31)SB16')
  security_note(0);
else if (version == '12.2(31)SB17')
  security_note(0);
else if (version == '12.2(31)SB18')
  security_note(0);
else if (version == '12.2(31)SB19')
  security_note(0);
else if (version == '12.2(31)SB1a')
  security_note(0);
else if (version == '12.2(31)SB1b')
  security_note(0);
else if (version == '12.2(31)SB1c')
  security_note(0);
else if (version == '12.2(31)SB1d')
  security_note(0);
else if (version == '12.2(31)SB1e')
  security_note(0);
else if (version == '12.2(31)SB1f')
  security_note(0);
else if (version == '12.2(31)SB1g')
  security_note(0);
else if (version == '12.2(31)SB2')
  security_note(0);
else if (version == '12.2(31)SB2a')
  security_note(0);
else if (version == '12.2(31)SB3')
  security_note(0);
else if (version == '12.2(31)SB3a')
  security_note(0);
else if (version == '12.2(31)SB3b')
  security_note(0);
else if (version == '12.2(31)SB3c')
  security_note(0);
else if (version == '12.2(31)SB3x')
  security_note(0);
else if (version == '12.2(31)SB4')
  security_note(0);
else if (version == '12.2(31)SB4a')
  security_note(0);
else if (version == '12.2(31)SB5')
  security_note(0);
else if (version == '12.2(31)SB5a')
  security_note(0);
else if (version == '12.2(31)SB6')
  security_note(0);
else if (version == '12.2(31)SB7')
  security_note(0);
else if (version == '12.2(31)SB8')
  security_note(0);
else if (version == '12.2(31)SB8a')
  security_note(0);
else if (version == '12.2(31)SB9')
  security_note(0);
else if (version == '12.2(31)SB9a')
  security_note(0);
else if (version == '12.2(31)SB9b')
  security_note(0);
else if (version == '12.2(31)SBY')
  security_note(0);
else if (version == '12.2(31)SBY1')
  security_note(0);
else if (version == '12.2(31)SG')
  security_note(0);
else if (version == '12.2(31)SG1')
  security_note(0);
else if (version == '12.2(31)SG2')
  security_note(0);
else if (version == '12.2(31)SG3')
  security_note(0);
else if (version == '12.2(31)SGA')
  security_note(0);
else if (version == '12.2(31)SGA1')
  security_note(0);
else if (version == '12.2(31)SGA10')
  security_note(0);
else if (version == '12.2(31)SGA11')
  security_note(0);
else if (version == '12.2(31)SGA2')
  security_note(0);
else if (version == '12.2(31)SGA3')
  security_note(0);
else if (version == '12.2(31)SGA4')
  security_note(0);
else if (version == '12.2(31)SGA5')
  security_note(0);
else if (version == '12.2(31)SGA6')
  security_note(0);
else if (version == '12.2(31)SGA7')
  security_note(0);
else if (version == '12.2(31)SGA8')
  security_note(0);
else if (version == '12.2(31)SGA9')
  security_note(0);
else if (version == '12.2(31)TST5')
  security_note(0);
else if (version == '12.2(31)XN')
  security_note(0);
else if (version == '12.2(31)XN1')
  security_note(0);
else if (version == '12.2(31)XN2')
  security_note(0);
else if (version == '12.2(31)XN3')
  security_note(0);
else if (version == '12.2(31)ZV')
  security_note(0);
else if (version == '12.2(31)ZV0a')
  security_note(0);
else if (version == '12.2(31)ZV0b')
  security_note(0);
else if (version == '12.2(31)ZV0c')
  security_note(0);
else if (version == '12.2(31)ZV0d')
  security_note(0);
else if (version == '12.2(31)ZV0e')
  security_note(0);
else if (version == '12.2(31)ZV0f')
  security_note(0);
else if (version == '12.2(31)ZV0g')
  security_note(0);
else if (version == '12.2(31)ZV0h')
  security_note(0);
else if (version == '12.2(31)ZV0i')
  security_note(0);
else if (version == '12.2(31)ZV0j')
  security_note(0);
else if (version == '12.2(31)ZV1a')
  security_note(0);
else if (version == '12.2(31)ZV1b')
  security_note(0);
else if (version == '12.2(31)ZV1c')
  security_note(0);
else if (version == '12.2(31)ZV2')
  security_note(0);
else if (version == '12.2(31)ZV2a')
  security_note(0);
else if (version == '12.2(31)ZV2b')
  security_note(0);
else if (version == '12.2(31)ZV2c')
  security_note(0);
else if (version == '12.2(33)IRA')
  security_note(0);
else if (version == '12.2(33)IRB')
  security_note(0);
else if (version == '12.2(33)IRC')
  security_note(0);
else if (version == '12.2(33)IRD')
  security_note(0);
else if (version == '12.2(33)IRE')
  security_note(0);
else if (version == '12.2(33)IRE1')
  security_note(0);
else if (version == '12.2(33)IRE2')
  security_note(0);
else if (version == '12.2(33)MRA')
  security_note(0);
else if (version == '12.2(33)MRB')
  security_note(0);
else if (version == '12.2(33)MRB1')
  security_note(0);
else if (version == '12.2(33)MRB2')
  security_note(0);
else if (version == '12.2(33)MRB3')
  security_note(0);
else if (version == '12.2(33)MRB4')
  security_note(0);
else if (version == '12.2(33r)SR')
  security_note(0);
else if (version == '12.2(33r)SRB')
  security_note(0);
else if (version == '12.2(33r)SRB1')
  security_note(0);
else if (version == '12.2(33r)SRB2')
  security_note(0);
else if (version == '12.2(33r)SRB3')
  security_note(0);
else if (version == '12.2(33r)SRB4')
  security_note(0);
else if (version == '12.2(33r)SRC')
  security_note(0);
else if (version == '12.2(33r)SRC1')
  security_note(0);
else if (version == '12.2(33r)SRC2')
  security_note(0);
else if (version == '12.2(33r)SRC3')
  security_note(0);
else if (version == '12.2(33r)SRC4')
  security_note(0);
else if (version == '12.2(33r)SRD')
  security_note(0);
else if (version == '12.2(33r)SRD1')
  security_note(0);
else if (version == '12.2(33r)SRD2')
  security_note(0);
else if (version == '12.2(33r)SRD3')
  security_note(0);
else if (version == '12.2(33r)SRD4')
  security_note(0);
else if (version == '12.2(33r)SRD5')
  security_note(0);
else if (version == '12.2(33r)SRD6')
  security_note(0);
else if (version == '12.2(33r)SRD7')
  security_note(0);
else if (version == '12.2(33r)XN')
  security_note(0);
else if (version == '12.2(33r)XN1')
  security_note(0);
else if (version == '12.2(33r)XN2')
  security_note(0);
else if (version == '12.2(33r)XN3')
  security_note(0);
else if (version == '12.2(33r)XNB')
  security_note(0);
else if (version == '12.2(33r)XNC')
  security_note(0);
else if (version == '12.2(33r)XND')
  security_note(0);
else if (version == '12.2(33r)XND1')
  security_note(0);
else if (version == '12.2(33)SB')
  security_note(0);
else if (version == '12.2(33)SB1')
  security_note(0);
else if (version == '12.2(33)SB1a')
  security_note(0);
else if (version == '12.2(33)SB1b')
  security_note(0);
else if (version == '12.2(33)SB2')
  security_note(0);
else if (version == '12.2(33)SB3')
  security_note(0);
else if (version == '12.2(33)SB4')
  security_note(0);
else if (version == '12.2(33)SB5')
  security_note(0);
else if (version == '12.2(33)SB6')
  security_note(0);
else if (version == '12.2(33)SB6a')
  security_note(0);
else if (version == '12.2(33)SB6b')
  security_note(0);
else if (version == '12.2(33)SB7')
  security_note(0);
else if (version == '12.2(33)SB8')
  security_note(0);
else if (version == '12.2(33)SB8a')
  security_note(0);
else if (version == '12.2(33)SB8b')
  security_note(0);
else if (version == '12.2(33)SB8c')
  security_note(0);
else if (version == '12.2(33)SB8d')
  security_note(0);
else if (version == '12.2(33)SB8e')
  security_note(0);
else if (version == '12.2(33)SB9')
  security_note(0);
else if (version == '12.2(33)SCA')
  security_note(0);
else if (version == '12.2(33)SCA1')
  security_note(0);
else if (version == '12.2(33)SCA2')
  security_note(0);
else if (version == '12.2(33)SCB')
  security_note(0);
else if (version == '12.2(33)SCB1')
  security_note(0);
else if (version == '12.2(33)SCB10')
  security_note(0);
else if (version == '12.2(33)SCB11')
  security_note(0);
else if (version == '12.2(33)SCB2')
  security_note(0);
else if (version == '12.2(33)SCB20081123')
  security_note(0);
else if (version == '12.2(33)SCB20081129')
  security_note(0);
else if (version == '12.2(33)SCB20081206')
  security_note(0);
else if (version == '12.2(33)SCB20081213')
  security_note(0);
else if (version == '12.2(33)SCB20090111')
  security_note(0);
else if (version == '12.2(33)SCB20090114')
  security_note(0);
else if (version == '12.2(33)SCB20090118')
  security_note(0);
else if (version == '12.2(33)SCB20090122')
  security_note(0);
else if (version == '12.2(33)SCB3')
  security_note(0);
else if (version == '12.2(33)SCB4')
  security_note(0);
else if (version == '12.2(33)SCB5')
  security_note(0);
else if (version == '12.2(33)SCB6')
  security_note(0);
else if (version == '12.2(33)SCB7')
  security_note(0);
else if (version == '12.2(33)SCB8')
  security_note(0);
else if (version == '12.2(33)SCB9')
  security_note(0);
else if (version == '12.2(33)SCC')
  security_note(0);
else if (version == '12.2(33)SCC1')
  security_note(0);
else if (version == '12.2(33)SCC2')
  security_note(0);
else if (version == '12.2(33)SCC3')
  security_note(0);
else if (version == '12.2(33)SCC4')
  security_note(0);
else if (version == '12.2(33)SCC5')
  security_note(0);
else if (version == '12.2(33)SCC6')
  security_note(0);
else if (version == '12.2(33)SCD')
  security_note(0);
else if (version == '12.2(33)SCD1')
  security_note(0);
else if (version == '12.2(33)SCD2')
  security_note(0);
else if (version == '12.2(33)SCD3')
  security_note(0);
else if (version == '12.2(33)SCD4')
  security_note(0);
else if (version == '12.2(33)SCD5')
  security_note(0);
else if (version == '12.2(33)SRA')
  security_note(0);
else if (version == '12.2(33)SRA1')
  security_note(0);
else if (version == '12.2(33)SRA2')
  security_note(0);
else if (version == '12.2(33)SRA3')
  security_note(0);
else if (version == '12.2(33)SRA5')
  security_note(0);
else if (version == '12.2(33)SRA6')
  security_note(0);
else if (version == '12.2(33)SRA7')
  security_note(0);
else if (version == '12.2(33)SRB')
  security_note(0);
else if (version == '12.2(33)SRB1')
  security_note(0);
else if (version == '12.2(33)SRB2')
  security_note(0);
else if (version == '12.2(33)SRB3')
  security_note(0);
else if (version == '12.2(33)SRB4')
  security_note(0);
else if (version == '12.2(33)SRB5')
  security_note(0);
else if (version == '12.2(33)SRB5a')
  security_note(0);
else if (version == '12.2(33)SRB6')
  security_note(0);
else if (version == '12.2(33)SRB7')
  security_note(0);
else if (version == '12.2(33)SRC')
  security_note(0);
else if (version == '12.2(33)SRC1')
  security_note(0);
else if (version == '12.2(33)SRC2')
  security_note(0);
else if (version == '12.2(33)SRC3')
  security_note(0);
else if (version == '12.2(33)SRC4')
  security_note(0);
else if (version == '12.2(33)SRC5')
  security_note(0);
else if (version == '12.2(33)SRC6')
  security_note(0);
else if (version == '12.2(33)SRD')
  security_note(0);
else if (version == '12.2(33)SRD1')
  security_note(0);
else if (version == '12.2(33)SRD2')
  security_note(0);
else if (version == '12.2(33)SRD2a')
  security_note(0);
else if (version == '12.2(33)SRD3')
  security_note(0);
else if (version == '12.2(33)SRD4')
  security_note(0);
else if (version == '12.2(33)SRD4a')
  security_note(0);
else if (version == '12.2(33)SRD5')
  security_note(0);
else if (version == '12.2(33)SRE')
  security_note(0);
else if (version == '12.2(33)SRE0a')
  security_note(0);
else if (version == '12.2(33)SRE1')
  security_note(0);
else if (version == '12.2(33)SRE2')
  security_note(0);
else if (version == '12.2(33)STE0')
  security_note(0);
else if (version == '12.2(33)STE1')
  security_note(0);
else if (version == '12.2(33)STE2')
  security_note(0);
else if (version == '12.2(33)STE3')
  security_note(0);
else if (version == '12.2(33)SXH')
  security_note(0);
else if (version == '12.2(33)SXH0a')
  security_note(0);
else if (version == '12.2(33)SXH1')
  security_note(0);
else if (version == '12.2(33)SXH2')
  security_note(0);
else if (version == '12.2(33)SXH2a')
  security_note(0);
else if (version == '12.2(33)SXH3')
  security_note(0);
else if (version == '12.2(33)SXH3a')
  security_note(0);
else if (version == '12.2(33)SXH4')
  security_note(0);
else if (version == '12.2(33)SXH5')
  security_note(0);
else if (version == '12.2(33)SXH6')
  security_note(0);
else if (version == '12.2(33)SXH7')
  security_note(0);
else if (version == '12.2(33)SXH7v')
  security_note(0);
else if (version == '12.2(33)SXH8')
  security_note(0);
else if (version == '12.2(33)SXI')
  security_note(0);
else if (version == '12.2(33)SXI1')
  security_note(0);
else if (version == '12.2(33)SXI2')
  security_note(0);
else if (version == '12.2(33)SXI2a')
  security_note(0);
else if (version == '12.2(33)SXI3')
  security_note(0);
else if (version == '12.2(33)SXI3a')
  security_note(0);
else if (version == '12.2(33)SXI3z')
  security_note(0);
else if (version == '12.2(33)SXI4')
  security_note(0);
else if (version == '12.2(33)SXI4a')
  security_note(0);
else if (version == '12.2(33)SXI5')
  security_note(0);
else if (version == '12.2(33)XN')
  security_note(0);
else if (version == '12.2(33)XN1')
  security_note(0);
else if (version == '12.2(33)XN2')
  security_note(0);
else if (version == '12.2(33)XN3')
  security_note(0);
else if (version == '12.2(33)XNA')
  security_note(0);
else if (version == '12.2(33)XNA1')
  security_note(0);
else if (version == '12.2(33)XNA2')
  security_note(0);
else if (version == '12.2(33)XNB')
  security_note(0);
else if (version == '12.2(33)XNB1')
  security_note(0);
else if (version == '12.2(33)XNB2')
  security_note(0);
else if (version == '12.2(33)XNB2b')
  security_note(0);
else if (version == '12.2(33)XNB3')
  security_note(0);
else if (version == '12.2(33)XNC')
  security_note(0);
else if (version == '12.2(33)XNC0a')
  security_note(0);
else if (version == '12.2(33)XNC0b')
  security_note(0);
else if (version == '12.2(33)XNC0c')
  security_note(0);
else if (version == '12.2(33)XNC0d')
  security_note(0);
else if (version == '12.2(33)XNC0e')
  security_note(0);
else if (version == '12.2(33)XNC0t')
  security_note(0);
else if (version == '12.2(33)XNC1')
  security_note(0);
else if (version == '12.2(33)XNC1t')
  security_note(0);
else if (version == '12.2(33)XNC2')
  security_note(0);
else if (version == '12.2(33)XND')
  security_note(0);
else if (version == '12.2(33)XND1')
  security_note(0);
else if (version == '12.2(33)XND2')
  security_note(0);
else if (version == '12.2(33)XND2t')
  security_note(0);
else if (version == '12.2(33)XND3')
  security_note(0);
else if (version == '12.2(33)XND4')
  security_note(0);
else if (version == '12.2(33)XNE')
  security_note(0);
else if (version == '12.2(33)XNE1')
  security_note(0);
else if (version == '12.2(33)XNE2')
  security_note(0);
else if (version == '12.2(33)XNF')
  security_note(0);
else if (version == '12.2(33)XNF1')
  security_note(0);
else if (version == '12.2(33)XNF2')
  security_note(0);
else if (version == '12.2(33)XNF613860897')
  security_note(0);
else if (version == '12.2(33)XNF613888093')
  security_note(0);
else if (version == '12.2(33)XNX')
  security_note(0);
else if (version == '12.2(33)XNX1')
  security_note(0);
else if (version == '12.2(33)XNX2')
  security_note(0);
else if (version == '12.2(33)XNX3')
  security_note(0);
else if (version == '12.2(33)XNZ')
  security_note(0);
else if (version == '12.2(33)ZI')
  security_note(0);
else if (version == '12.2(33)ZW')
  security_note(0);
else if (version == '12.2(33)ZZ')
  security_note(0);
else if (version == '12.2(34)SB')
  security_note(0);
else if (version == '12.2(34)SB1')
  security_note(0);
else if (version == '12.2(34)SB2')
  security_note(0);
else if (version == '12.2(34)SB3')
  security_note(0);
else if (version == '12.2(34)SB4')
  security_note(0);
else if (version == '12.2(34)SB4a')
  security_note(0);
else if (version == '12.2(34)SB4b')
  security_note(0);
else if (version == '12.2(34)SB4c')
  security_note(0);
else if (version == '12.2(34)SB4d')
  security_note(0);
else if (version == '12.2(3a)')
  security_note(0);
else if (version == '12.2(3b)')
  security_note(0);
else if (version == '12.2(3c)')
  security_note(0);
else if (version == '12.2(3d)')
  security_note(0);
else if (version == '12.2(3e)')
  security_note(0);
else if (version == '12.2(3f)')
  security_note(0);
else if (version == '12.2(3g)')
  security_note(0);
else if (version == '12.2(3)SBT112')
  security_note(0);
else if (version == '12.2(4)B')
  security_note(0);
else if (version == '12.2(4)B')
  security_note(0);
else if (version == '12.2(4)B1')
  security_note(0);
else if (version == '12.2(4)B1')
  security_note(0);
else if (version == '12.2(4)B2')
  security_note(0);
else if (version == '12.2(4)B2')
  security_note(0);
else if (version == '12.2(4)B3')
  security_note(0);
else if (version == '12.2(4)B3')
  security_note(0);
else if (version == '12.2(4)B4')
  security_note(0);
else if (version == '12.2(4)B4')
  security_note(0);
else if (version == '12.2(4)B5')
  security_note(0);
else if (version == '12.2(4)B5')
  security_note(0);
else if (version == '12.2(4)B6')
  security_note(0);
else if (version == '12.2(4)B6')
  security_note(0);
else if (version == '12.2(4)B7')
  security_note(0);
else if (version == '12.2(4)B7')
  security_note(0);
else if (version == '12.2(4)B7a')
  security_note(0);
else if (version == '12.2(4)B7a')
  security_note(0);
else if (version == '12.2(4)B8')
  security_note(0);
else if (version == '12.2(4)B8')
  security_note(0);
else if (version == '12.2(4)BC1')
  security_note(0);
else if (version == '12.2(4)BC1')
  security_note(0);
else if (version == '12.2(4)BC1a')
  security_note(0);
else if (version == '12.2(4)BC1a')
  security_note(0);
else if (version == '12.2(4)BC1b')
  security_note(0);
else if (version == '12.2(4)BC1b')
  security_note(0);
else if (version == '12.2(4)BW')
  security_note(0);
else if (version == '12.2(4)BW')
  security_note(0);
else if (version == '12.2(4)BW1')
  security_note(0);
else if (version == '12.2(4)BW1')
  security_note(0);
else if (version == '12.2(4)BW1a')
  security_note(0);
else if (version == '12.2(4)BW1a')
  security_note(0);
else if (version == '12.2(4)BW2')
  security_note(0);
else if (version == '12.2(4)BW2')
  security_note(0);
else if (version == '12.2(4)BX')
  security_note(0);
else if (version == '12.2(4)BX')
  security_note(0);
else if (version == '12.2(4)BX1')
  security_note(0);
else if (version == '12.2(4)BX1')
  security_note(0);
else if (version == '12.2(4)BX1a')
  security_note(0);
else if (version == '12.2(4)BX1a')
  security_note(0);
else if (version == '12.2(4)BX1b')
  security_note(0);
else if (version == '12.2(4)BX1b')
  security_note(0);
else if (version == '12.2(4)BX1c')
  security_note(0);
else if (version == '12.2(4)BX1c')
  security_note(0);
else if (version == '12.2(4)BX1d')
  security_note(0);
else if (version == '12.2(4)BX1d')
  security_note(0);
else if (version == '12.2(4)BX2')
  security_note(0);
else if (version == '12.2(4)BX2')
  security_note(0);
else if (version == '12.2(4)BY')
  security_note(0);
else if (version == '12.2(4)BY')
  security_note(0);
else if (version == '12.2(4)BY1')
  security_note(0);
else if (version == '12.2(4)BY1')
  security_note(0);
else if (version == '12.2(4)JA')
  security_note(0);
else if (version == '12.2(4)JA')
  security_note(0);
else if (version == '12.2(4)JA1')
  security_note(0);
else if (version == '12.2(4)JA1')
  security_note(0);
else if (version == '12.2(4)MB1')
  security_note(0);
else if (version == '12.2(4)MB1')
  security_note(0);
else if (version == '12.2(4)MB10')
  security_note(0);
else if (version == '12.2(4)MB10')
  security_note(0);
else if (version == '12.2(4)MB11')
  security_note(0);
else if (version == '12.2(4)MB11')
  security_note(0);
else if (version == '12.2(4)MB12')
  security_note(0);
else if (version == '12.2(4)MB12')
  security_note(0);
else if (version == '12.2(4)MB13')
  security_note(0);
else if (version == '12.2(4)MB13')
  security_note(0);
else if (version == '12.2(4)MB13a')
  security_note(0);
else if (version == '12.2(4)MB13a')
  security_note(0);
else if (version == '12.2(4)MB13b')
  security_note(0);
else if (version == '12.2(4)MB13b')
  security_note(0);
else if (version == '12.2(4)MB13c')
  security_note(0);
else if (version == '12.2(4)MB13c')
  security_note(0);
else if (version == '12.2(4)MB2')
  security_note(0);
else if (version == '12.2(4)MB2')
  security_note(0);
else if (version == '12.2(4)MB3')
  security_note(0);
else if (version == '12.2(4)MB3')
  security_note(0);
else if (version == '12.2(4)MB4')
  security_note(0);
else if (version == '12.2(4)MB4')
  security_note(0);
else if (version == '12.2(4)MB5')
  security_note(0);
else if (version == '12.2(4)MB5')
  security_note(0);
else if (version == '12.2(4)MB6')
  security_note(0);
else if (version == '12.2(4)MB6')
  security_note(0);
else if (version == '12.2(4)MB7')
  security_note(0);
else if (version == '12.2(4)MB7')
  security_note(0);
else if (version == '12.2(4)MB8')
  security_note(0);
else if (version == '12.2(4)MB8')
  security_note(0);
else if (version == '12.2(4)MB9')
  security_note(0);
else if (version == '12.2(4)MB9')
  security_note(0);
else if (version == '12.2(4)MB9a')
  security_note(0);
else if (version == '12.2(4)MB9a')
  security_note(0);
else if (version == '12.2(4)MX')
  security_note(0);
else if (version == '12.2(4)MX')
  security_note(0);
else if (version == '12.2(4)MX1')
  security_note(0);
else if (version == '12.2(4)MX1')
  security_note(0);
else if (version == '12.2(4)MX2')
  security_note(0);
else if (version == '12.2(4)MX2')
  security_note(0);
else if (version == '12.2(4r)B')
  security_note(0);
else if (version == '12.2(4r)B')
  security_note(0);
else if (version == '12.2(4r)B1')
  security_note(0);
else if (version == '12.2(4r)B1')
  security_note(0);
else if (version == '12.2(4r)B2')
  security_note(0);
else if (version == '12.2(4r)B2')
  security_note(0);
else if (version == '12.2(4r)B3')
  security_note(0);
else if (version == '12.2(4r)B3')
  security_note(0);
else if (version == '12.2(4r)B4')
  security_note(0);
else if (version == '12.2(4r)B4')
  security_note(0);
else if (version == '12.2(4r)T')
  security_note(0);
else if (version == '12.2(4r)T1')
  security_note(0);
else if (version == '12.2(4r)XL')
  security_note(0);
else if (version == '12.2(4r)XL')
  security_note(0);
else if (version == '12.2(4r)XM')
  security_note(0);
else if (version == '12.2(4r)XM')
  security_note(0);
else if (version == '12.2(4r)XM')
  security_note(0);
else if (version == '12.2(4r)XM1')
  security_note(0);
else if (version == '12.2(4r)XM1')
  security_note(0);
else if (version == '12.2(4r)XM1')
  security_note(0);
else if (version == '12.2(4r)XM2')
  security_note(0);
else if (version == '12.2(4r)XM2')
  security_note(0);
else if (version == '12.2(4r)XM2')
  security_note(0);
else if (version == '12.2(4r)XM3')
  security_note(0);
else if (version == '12.2(4r)XM3')
  security_note(0);
else if (version == '12.2(4r)XM3')
  security_note(0);
else if (version == '12.2(4r)XM4')
  security_note(0);
else if (version == '12.2(4r)XM4')
  security_note(0);
else if (version == '12.2(4r)XM4')
  security_note(0);
else if (version == '12.2(4r)XT')
  security_note(0);
else if (version == '12.2(4r)XT')
  security_note(0);
else if (version == '12.2(4r)XT1')
  security_note(0);
else if (version == '12.2(4r)XT1')
  security_note(0);
else if (version == '12.2(4r)XT2')
  security_note(0);
else if (version == '12.2(4r)XT2')
  security_note(0);
else if (version == '12.2(4r)XT3')
  security_note(0);
else if (version == '12.2(4r)XT3')
  security_note(0);
else if (version == '12.2(4r)XT4')
  security_note(0);
else if (version == '12.2(4r)XT4')
  security_note(0);
else if (version == '12.2(4)SBT112')
  security_note(0);
else if (version == '12.2(4)T')
  security_note(0);
else if (version == '12.2(4)T')
  security_note(0);
else if (version == '12.2(4)T1')
  security_note(0);
else if (version == '12.2(4)T1')
  security_note(0);
else if (version == '12.2(4)T2')
  security_note(0);
else if (version == '12.2(4)T2')
  security_note(0);
else if (version == '12.2(4)T3')
  security_note(0);
else if (version == '12.2(4)T3')
  security_note(0);
else if (version == '12.2(4)T4')
  security_note(0);
else if (version == '12.2(4)T4')
  security_note(0);
else if (version == '12.2(4)T5')
  security_note(0);
else if (version == '12.2(4)T5')
  security_note(0);
else if (version == '12.2(4)T6')
  security_note(0);
else if (version == '12.2(4)T6')
  security_note(0);
else if (version == '12.2(4)T7')
  security_note(0);
else if (version == '12.2(4)T7')
  security_note(0);
else if (version == '12.2(4)XF')
  security_note(0);
else if (version == '12.2(4)XF')
  security_note(0);
else if (version == '12.2(4)XF1')
  security_note(0);
else if (version == '12.2(4)XF1')
  security_note(0);
else if (version == '12.2(4)XL')
  security_note(0);
else if (version == '12.2(4)XL')
  security_note(0);
else if (version == '12.2(4)XL')
  security_note(0);
else if (version == '12.2(4)XL1')
  security_note(0);
else if (version == '12.2(4)XL1')
  security_note(0);
else if (version == '12.2(4)XL1')
  security_note(0);
else if (version == '12.2(4)XL2')
  security_note(0);
else if (version == '12.2(4)XL2')
  security_note(0);
else if (version == '12.2(4)XL2')
  security_note(0);
else if (version == '12.2(4)XL3')
  security_note(0);
else if (version == '12.2(4)XL3')
  security_note(0);
else if (version == '12.2(4)XL3')
  security_note(0);
else if (version == '12.2(4)XL4')
  security_note(0);
else if (version == '12.2(4)XL4')
  security_note(0);
else if (version == '12.2(4)XL4')
  security_note(0);
else if (version == '12.2(4)XL5')
  security_note(0);
else if (version == '12.2(4)XL5')
  security_note(0);
else if (version == '12.2(4)XL5')
  security_note(0);
else if (version == '12.2(4)XL6')
  security_note(0);
else if (version == '12.2(4)XL6')
  security_note(0);
else if (version == '12.2(4)XL6')
  security_note(0);
else if (version == '12.2(4)XM')
  security_note(0);
else if (version == '12.2(4)XM')
  security_note(0);
else if (version == '12.2(4)XM')
  security_note(0);
else if (version == '12.2(4)XM1')
  security_note(0);
else if (version == '12.2(4)XM1')
  security_note(0);
else if (version == '12.2(4)XM1')
  security_note(0);
else if (version == '12.2(4)XM2')
  security_note(0);
else if (version == '12.2(4)XM2')
  security_note(0);
else if (version == '12.2(4)XM2')
  security_note(0);
else if (version == '12.2(4)XM3')
  security_note(0);
else if (version == '12.2(4)XM3')
  security_note(0);
else if (version == '12.2(4)XM3')
  security_note(0);
else if (version == '12.2(4)XM4')
  security_note(0);
else if (version == '12.2(4)XM4')
  security_note(0);
else if (version == '12.2(4)XM4')
  security_note(0);
else if (version == '12.2(4)XR')
  security_note(0);
else if (version == '12.2(4)XR')
  security_note(0);
else if (version == '12.2(4)XV')
  security_note(0);
else if (version == '12.2(4)XV')
  security_note(0);
else if (version == '12.2(4)XV1')
  security_note(0);
else if (version == '12.2(4)XV1')
  security_note(0);
else if (version == '12.2(4)XV2')
  security_note(0);
else if (version == '12.2(4)XV2')
  security_note(0);
else if (version == '12.2(4)XV3')
  security_note(0);
else if (version == '12.2(4)XV3')
  security_note(0);
else if (version == '12.2(4)XV4')
  security_note(0);
else if (version == '12.2(4)XV4')
  security_note(0);
else if (version == '12.2(4)XV4a')
  security_note(0);
else if (version == '12.2(4)XV4a')
  security_note(0);
else if (version == '12.2(4)XV5')
  security_note(0);
else if (version == '12.2(4)XV5')
  security_note(0);
else if (version == '12.2(4)XW')
  security_note(0);
else if (version == '12.2(4)XW')
  security_note(0);
else if (version == '12.2(4)XZ')
  security_note(0);
else if (version == '12.2(4)XZ')
  security_note(0);
else if (version == '12.2(4)XZ1')
  security_note(0);
else if (version == '12.2(4)XZ1')
  security_note(0);
else if (version == '12.2(4)XZ2')
  security_note(0);
else if (version == '12.2(4)XZ2')
  security_note(0);
else if (version == '12.2(4)XZ3')
  security_note(0);
else if (version == '12.2(4)XZ3')
  security_note(0);
else if (version == '12.2(4)XZ4')
  security_note(0);
else if (version == '12.2(4)XZ4')
  security_note(0);
else if (version == '12.2(4)XZ5')
  security_note(0);
else if (version == '12.2(4)XZ5')
  security_note(0);
else if (version == '12.2(4)XZ6')
  security_note(0);
else if (version == '12.2(4)XZ6')
  security_note(0);
else if (version == '12.2(4)XZ7')
  security_note(0);
else if (version == '12.2(4)XZ7')
  security_note(0);
else if (version == '12.2(4)YA')
  security_note(0);
else if (version == '12.2(4)YA')
  security_note(0);
else if (version == '12.2(4)YA')
  security_note(0);
else if (version == '12.2(4)YA1')
  security_note(0);
else if (version == '12.2(4)YA1')
  security_note(0);
else if (version == '12.2(4)YA1')
  security_note(0);
else if (version == '12.2(4)YA10')
  security_note(0);
else if (version == '12.2(4)YA10')
  security_note(0);
else if (version == '12.2(4)YA10')
  security_note(0);
else if (version == '12.2(4)YA11')
  security_note(0);
else if (version == '12.2(4)YA11')
  security_note(0);
else if (version == '12.2(4)YA11')
  security_note(0);
else if (version == '12.2(4)YA12')
  security_note(0);
else if (version == '12.2(4)YA12')
  security_note(0);
else if (version == '12.2(4)YA2')
  security_note(0);
else if (version == '12.2(4)YA2')
  security_note(0);
else if (version == '12.2(4)YA2')
  security_note(0);
else if (version == '12.2(4)YA3')
  security_note(0);
else if (version == '12.2(4)YA3')
  security_note(0);
else if (version == '12.2(4)YA3')
  security_note(0);
else if (version == '12.2(4)YA4')
  security_note(0);
else if (version == '12.2(4)YA4')
  security_note(0);
else if (version == '12.2(4)YA4')
  security_note(0);
else if (version == '12.2(4)YA5')
  security_note(0);
else if (version == '12.2(4)YA5')
  security_note(0);
else if (version == '12.2(4)YA5')
  security_note(0);
else if (version == '12.2(4)YA6')
  security_note(0);
else if (version == '12.2(4)YA6')
  security_note(0);
else if (version == '12.2(4)YA6')
  security_note(0);
else if (version == '12.2(4)YA7')
  security_note(0);
else if (version == '12.2(4)YA7')
  security_note(0);
else if (version == '12.2(4)YA7')
  security_note(0);
else if (version == '12.2(4)YA8')
  security_note(0);
else if (version == '12.2(4)YA8')
  security_note(0);
else if (version == '12.2(4)YA8')
  security_note(0);
else if (version == '12.2(4)YA9')
  security_note(0);
else if (version == '12.2(4)YA9')
  security_note(0);
else if (version == '12.2(4)YA9')
  security_note(0);
else if (version == '12.2(4)YB')
  security_note(0);
else if (version == '12.2(4)YB')
  security_note(0);
else if (version == '12.2(4)YF')
  security_note(0);
else if (version == '12.2(4)YF')
  security_note(0);
else if (version == '12.2(4)YH')
  security_note(0);
else if (version == '12.2(4)YH')
  security_note(0);
else if (version == '12.2(5)')
  security_note(0);
else if (version == '12.2(5a)')
  security_note(0);
else if (version == '12.2(5b)')
  security_note(0);
else if (version == '12.2(5c)')
  security_note(0);
else if (version == '12.2(5d)')
  security_note(0);
else if (version == '12.2(5)DA')
  security_note(0);
else if (version == '12.2(5)DA1')
  security_note(0);
else if (version == '12.2(5)SBT112')
  security_note(0);
else if (version == '12.2(6)')
  security_note(0);
else if (version == '12.2(6a)')
  security_note(0);
else if (version == '12.2(6b)')
  security_note(0);
else if (version == '12.2(6c)')
  security_note(0);
else if (version == '12.2(6c)M1')
  security_note(0);
else if (version == '12.2(6c)TEST')
  security_note(0);
else if (version == '12.2(6d)')
  security_note(0);
else if (version == '12.2(6e)')
  security_note(0);
else if (version == '12.2(6f)')
  security_note(0);
else if (version == '12.2(6f)M1')
  security_note(0);
else if (version == '12.2(6g)')
  security_note(0);
else if (version == '12.2(6h)')
  security_note(0);
else if (version == '12.2(6i)')
  security_note(0);
else if (version == '12.2(6j)')
  security_note(0);
else if (version == '12.2(6r)')
  security_note(0);
else if (version == '12.2(7)')
  security_note(0);
else if (version == '12.2(7a)')
  security_note(0);
else if (version == '12.2(7b)')
  security_note(0);
else if (version == '12.2(7c)')
  security_note(0);
else if (version == '12.2(7d)')
  security_note(0);
else if (version == '12.2(7)DA')
  security_note(0);
else if (version == '12.2(7)DA')
  security_note(0);
else if (version == '12.2(7e)')
  security_note(0);
else if (version == '12.2(7f)')
  security_note(0);
else if (version == '12.2(7g)')
  security_note(0);
else if (version == '12.2(7r)')
  security_note(0);
else if (version == '12.2(7r)EY')
  security_note(0);
else if (version == '12.2(7r)XM')
  security_note(0);
else if (version == '12.2(7r)XM')
  security_note(0);
else if (version == '12.2(7r)XM1')
  security_note(0);
else if (version == '12.2(7r)XM1')
  security_note(0);
else if (version == '12.2(7r)XM2')
  security_note(0);
else if (version == '12.2(7r)XM2')
  security_note(0);
else if (version == '12.2(7r)XM3')
  security_note(0);
else if (version == '12.2(7r)XM3')
  security_note(0);
else if (version == '12.2(7r)XM4')
  security_note(0);
else if (version == '12.2(7r)XM4')
  security_note(0);
else if (version == '12.2(7r)XM5')
  security_note(0);
else if (version == '12.2(7r)XM5')
  security_note(0);
else if (version == '12.2(7)SBT112')
  security_note(0);
else if (version == '12.2(8)B')
  security_note(0);
else if (version == '12.2(8)B')
  security_note(0);
else if (version == '12.2(8)B1')
  security_note(0);
else if (version == '12.2(8)B1')
  security_note(0);
else if (version == '12.2(8)B2')
  security_note(0);
else if (version == '12.2(8)B2')
  security_note(0);
else if (version == '12.2(8)BC1')
  security_note(0);
else if (version == '12.2(8)BC1')
  security_note(0);
else if (version == '12.2(8)BC2')
  security_note(0);
else if (version == '12.2(8)BC2')
  security_note(0);
else if (version == '12.2(8)BC2a')
  security_note(0);
else if (version == '12.2(8)BC2a')
  security_note(0);
else if (version == '12.2(8)BY')
  security_note(0);
else if (version == '12.2(8)BY')
  security_note(0);
else if (version == '12.2(8)BY1')
  security_note(0);
else if (version == '12.2(8)BY1')
  security_note(0);
else if (version == '12.2(8)BY2')
  security_note(0);
else if (version == '12.2(8)BY2')
  security_note(0);
else if (version == '12.2(8)BZ')
  security_note(0);
else if (version == '12.2(8)BZ')
  security_note(0);
else if (version == '12.2(8)JA')
  security_note(0);
else if (version == '12.2(8)JA')
  security_note(0);
else if (version == '12.2(8)MC1')
  security_note(0);
else if (version == '12.2(8)MC1')
  security_note(0);
else if (version == '12.2(8)MC2')
  security_note(0);
else if (version == '12.2(8)MC2')
  security_note(0);
else if (version == '12.2(8)MC2a')
  security_note(0);
else if (version == '12.2(8)MC2a')
  security_note(0);
else if (version == '12.2(8)MC2b')
  security_note(0);
else if (version == '12.2(8)MC2b')
  security_note(0);
else if (version == '12.2(8)MC2c')
  security_note(0);
else if (version == '12.2(8)MC2c')
  security_note(0);
else if (version == '12.2(8)MC2d')
  security_note(0);
else if (version == '12.2(8)MC2d')
  security_note(0);
else if (version == '12.2(8r)')
  security_note(0);
else if (version == '12.2(8r)B')
  security_note(0);
else if (version == '12.2(8r)B')
  security_note(0);
else if (version == '12.2(8r)B1')
  security_note(0);
else if (version == '12.2(8r)B1')
  security_note(0);
else if (version == '12.2(8r)B2')
  security_note(0);
else if (version == '12.2(8r)B2')
  security_note(0);
else if (version == '12.2(8r)B3')
  security_note(0);
else if (version == '12.2(8r)B3')
  security_note(0);
else if (version == '12.2(8r)B3a')
  security_note(0);
else if (version == '12.2(8r)B3a')
  security_note(0);
else if (version == '12.2(8r)MC1')
  security_note(0);
else if (version == '12.2(8r)MC1')
  security_note(0);
else if (version == '12.2(8r)MC2')
  security_note(0);
else if (version == '12.2(8r)MC2')
  security_note(0);
else if (version == '12.2(8r)MC3')
  security_note(0);
else if (version == '12.2(8r)MC3')
  security_note(0);
else if (version == '12.2(8r)T')
  security_note(0);
else if (version == '12.2(8r)T')
  security_note(0);
else if (version == '12.2(8r)T1')
  security_note(0);
else if (version == '12.2(8r)T1')
  security_note(0);
else if (version == '12.2(8r)T2')
  security_note(0);
else if (version == '12.2(8r)T2')
  security_note(0);
else if (version == '12.2(8r)T3')
  security_note(0);
else if (version == '12.2(8r)T3')
  security_note(0);
else if (version == '12.2(8)SBT112')
  security_note(0);
else if (version == '12.2(8)T')
  security_note(0);
else if (version == '12.2(8)T')
  security_note(0);
else if (version == '12.2(8)T0a')
  security_note(0);
else if (version == '12.2(8)T0a')
  security_note(0);
else if (version == '12.2(8)T0b')
  security_note(0);
else if (version == '12.2(8)T0b')
  security_note(0);
else if (version == '12.2(8)T0c')
  security_note(0);
else if (version == '12.2(8)T0c')
  security_note(0);
else if (version == '12.2(8)T0d')
  security_note(0);
else if (version == '12.2(8)T0d')
  security_note(0);
else if (version == '12.2(8)T0e')
  security_note(0);
else if (version == '12.2(8)T0e')
  security_note(0);
else if (version == '12.2(8)T1')
  security_note(0);
else if (version == '12.2(8)T1')
  security_note(0);
else if (version == '12.2(8)T10')
  security_note(0);
else if (version == '12.2(8)T10')
  security_note(0);
else if (version == '12.2(8)T2')
  security_note(0);
else if (version == '12.2(8)T2')
  security_note(0);
else if (version == '12.2(8)T3')
  security_note(0);
else if (version == '12.2(8)T3')
  security_note(0);
else if (version == '12.2(8)T4')
  security_note(0);
else if (version == '12.2(8)T4')
  security_note(0);
else if (version == '12.2(8)T4a')
  security_note(0);
else if (version == '12.2(8)T4a')
  security_note(0);
else if (version == '12.2(8)T5')
  security_note(0);
else if (version == '12.2(8)T5')
  security_note(0);
else if (version == '12.2(8)T6')
  security_note(0);
else if (version == '12.2(8)T6')
  security_note(0);
else if (version == '12.2(8)T7')
  security_note(0);
else if (version == '12.2(8)T7')
  security_note(0);
else if (version == '12.2(8)T8')
  security_note(0);
else if (version == '12.2(8)T8')
  security_note(0);
else if (version == '12.2(8)T9')
  security_note(0);
else if (version == '12.2(8)T9')
  security_note(0);
else if (version == '12.2(8)TPC10a')
  security_note(0);
else if (version == '12.2(8)TPC10a')
  security_note(0);
else if (version == '12.2(8)TPC10b')
  security_note(0);
else if (version == '12.2(8)TPC10b')
  security_note(0);
else if (version == '12.2(8)TPC10c')
  security_note(0);
else if (version == '12.2(8)TPC10c')
  security_note(0);
else if (version == '12.2(8)YD')
  security_note(0);
else if (version == '12.2(8)YD')
  security_note(0);
else if (version == '12.2(8)YD1')
  security_note(0);
else if (version == '12.2(8)YD1')
  security_note(0);
else if (version == '12.2(8)YD2')
  security_note(0);
else if (version == '12.2(8)YD2')
  security_note(0);
else if (version == '12.2(8)YD3')
  security_note(0);
else if (version == '12.2(8)YD3')
  security_note(0);
else if (version == '12.2(8)YJ')
  security_note(0);
else if (version == '12.2(8)YJ')
  security_note(0);
else if (version == '12.2(8)YJ1')
  security_note(0);
else if (version == '12.2(8)YJ1')
  security_note(0);
else if (version == '12.2(8)YN')
  security_note(0);
else if (version == '12.2(8)YN1')
  security_note(0);
else if (version == '12.2(8)YY')
  security_note(0);
else if (version == '12.2(8)YY')
  security_note(0);
else if (version == '12.2(8)YY1')
  security_note(0);
else if (version == '12.2(8)YY1')
  security_note(0);
else if (version == '12.2(8)YY2')
  security_note(0);
else if (version == '12.2(8)YY2')
  security_note(0);
else if (version == '12.2(8)YY3')
  security_note(0);
else if (version == '12.2(8)YY3')
  security_note(0);
else if (version == '12.2(8)YY4')
  security_note(0);
else if (version == '12.2(8)YY4')
  security_note(0);
else if (version == '12.2(8)ZB')
  security_note(0);
else if (version == '12.2(8)ZB')
  security_note(0);
else if (version == '12.2(8)ZB1')
  security_note(0);
else if (version == '12.2(8)ZB1')
  security_note(0);
else if (version == '12.2(8)ZB2')
  security_note(0);
else if (version == '12.2(8)ZB2')
  security_note(0);
else if (version == '12.2(8)ZB3')
  security_note(0);
else if (version == '12.2(8)ZB3')
  security_note(0);
else if (version == '12.2(8)ZB4')
  security_note(0);
else if (version == '12.2(8)ZB4')
  security_note(0);
else if (version == '12.2(8)ZB4a')
  security_note(0);
else if (version == '12.2(8)ZB4a')
  security_note(0);
else if (version == '12.2(8)ZB5')
  security_note(0);
else if (version == '12.2(8)ZB5')
  security_note(0);
else if (version == '12.2(8)ZB6')
  security_note(0);
else if (version == '12.2(8)ZB6')
  security_note(0);
else if (version == '12.2(8)ZB7')
  security_note(0);
else if (version == '12.2(8)ZB7')
  security_note(0);
else if (version == '12.2(8)ZB8')
  security_note(0);
else if (version == '12.2(8)ZB8')
  security_note(0);
else if (version == '12.2(92)TST')
  security_note(0);
else if (version == '12.2(92)TST1')
  security_note(0);
else if (version == '12.2(92)TST2')
  security_note(0);
else if (version == '12.2(9909)TEST')
  security_note(0);
else if (version == '12.2(9990)CCAI')
  security_note(0);
else if (version == '12.2(9999)CCAI')
  security_note(0);
else if (version == '12.2(9999)SRA')
  security_note(0);
else if (version == '12.2(9999)SRA2')
  security_note(0);
else if (version == '12.2(999)SXI')
  security_note(0);
else if (version == '12.2(99)SX1003')
  security_note(0);
else if (version == '12.2(99)SX1004')
  security_note(0);
else if (version == '12.2(99)SX1005')
  security_note(0);
else if (version == '12.2(99)SX1006')
  security_note(0);
else if (version == '12.2(99)SX1007')
  security_note(0);
else if (version == '12.2(99)SX1008')
  security_note(0);
else if (version == '12.2(99)SX1009')
  security_note(0);
else if (version == '12.2(99)SX1010')
  security_note(0);
else if (version == '12.2(99)SX1011')
  security_note(0);
else if (version == '12.2(99)SX1012')
  security_note(0);
else if (version == '12.2(99)SX1013')
  security_note(0);
else if (version == '12.2(99)SX1014')
  security_note(0);
else if (version == '12.2(99)SX1015')
  security_note(0);
else if (version == '12.2(99)SX1016')
  security_note(0);
else if (version == '12.2(99)SX1017')
  security_note(0);
else if (version == '12.2(99)SX1018')
  security_note(0);
else if (version == '12.2(99)SX1019')
  security_note(0);
else if (version == '12.2(99)SX1020')
  security_note(0);
else if (version == '12.2(99)SX1021')
  security_note(0);
else if (version == '12.2(99)SX1022')
  security_note(0);
else if (version == '12.2(99)SX1023')
  security_note(0);
else if (version == '12.2(99)SX1024')
  security_note(0);
else if (version == '12.2(99)SX1025')
  security_note(0);
else if (version == '12.2(99)SX1026')
  security_note(0);
else if (version == '12.2(99)SX1027')
  security_note(0);
else if (version == '12.2(99)SX1028')
  security_note(0);
else if (version == '12.2(99)SX1029')
  security_note(0);
else if (version == '12.2(99)SX1031')
  security_note(0);
else if (version == '12.2(99)SX1031a')
  security_note(0);
else if (version == '12.2(99)SX1032')
  security_note(0);
else if (version == '12.2(99)SX1033')
  security_note(0);
else if (version == '12.2(99)SX1034')
  security_note(0);
else if (version == '12.2(99)SX1035')
  security_note(0);
else if (version == '12.2(99)SX2000')
  security_note(0);
else if (version == '12.2(99)SX2001')
  security_note(0);
else if (version == '12.2(99)SX2002')
  security_note(0);
else if (version == '12.2(99)SX2003')
  security_note(0);
else if (version == '12.2(99)SX2004')
  security_note(0);
else if (version == '12.2(99)SX2006')
  security_note(0);
else if (version == '12.2(99)SX2007')
  security_note(0);
else if (version == '12.2(99)SX2008')
  security_note(0);
else if (version == '12.2(99)SX2009')
  security_note(0);
else if (version == '12.2(99)SX2010')
  security_note(0);
else if (version == '12.2(99)SX3000')
  security_note(0);
else if (version == '12.2(99)SX3001')
  security_note(0);
else if (version == '12.2(99)SX4000')
  security_note(0);
else if (version == '12.2(99)TEST2')
  security_note(0);
else if (version == '12.2(9)S')
  security_note(0);
else if (version == '12.2(9)SBT112')
  security_note(0);
else if (version == '12.2(9)YE')
  security_note(0);
else if (version == '12.2(9)YO')
  security_note(0);
else if (version == '12.2(9)YO')
  security_note(0);
else if (version == '12.2(9)YO1')
  security_note(0);
else if (version == '12.2(9)YO1')
  security_note(0);
else if (version == '12.2(9)YO2')
  security_note(0);
else if (version == '12.2(9)YO2')
  security_note(0);
else if (version == '12.2(9)YO3')
  security_note(0);
else if (version == '12.2(9)YO3')
  security_note(0);
else if (version == '12.2(9)YO4')
  security_note(0);
else if (version == '12.2(9)YO4')
  security_note(0);
else if (version == '12.2(9)ZA')
  security_note(0);
else if (version == '12.2(9)ZA')
  security_note(0);
else if (version == '12.3(1)')
  security_note(0);
else if (version == '12.3(10r)')
  security_note(0);
else if (version == '12.3(10r)')
  security_note(0);
else if (version == '12.3(18r)S1')
  security_note(0);
else if (version == '12.3(18r)S2')
  security_note(0);
else if (version == '12.3(18r)SX1')
  security_note(0);
else if (version == '12.3(1a)')
  security_note(0);
else if (version == '12.3(1a)B')
  security_note(0);
else if (version == '12.3(1a)BW')
  security_note(0);
else if (version == '12.3(1)FIPS140')
  security_note(0);
else if (version == '12.4(123e)TST')
  security_note(0);
else if (version == '12.4(123g)TST')
  security_note(0);
else if (version == '12.4(567b)TST')
  security_note(0);
else if (version == '12.4(789a)TST')
  security_note(0);
else if (version == '12.5(98)TST')
  security_note(0);
else if (version == '12.9(9)S0225')
  security_note(0);
else if (version == '15.0(1r)S')
  security_note(0);
else if (version == '15.0(1)S')
  security_note(0);
else if (version == '15.0(1)S1')
  security_note(0);
else if (version == '15.0(99)TST')
  security_note(0);
else if (version == '15.1(1)S')
  security_note(0);
else
  audit(AUDIT_HOST_NOT, 'affected');
