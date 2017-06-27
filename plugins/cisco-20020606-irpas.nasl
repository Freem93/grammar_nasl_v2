#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17773);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id("CVE-2002-2053");
  script_bugtraq_id(4949);
  script_osvdb_id(60031);
  script_xref(name:"CISCO-BUG-ID", value:"CSCdu38323");
  
  script_name(english:"Cisco IOS Hot Standby Routing Protocol IP Collision Denial of Service");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The design of the Hot Standby Routing Protocol, when using IRPAS,
allows remote attackers to cause a denial of service via a router with
the same IP address as the interface on which HSRP is running.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jun/33");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch, which can be obtained from the Cisco Bug
tracker.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/06/06");
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

if (version == '12.0(10r)S')
  security_warning(0);
else if (version == '12.0(10r)S1')
  security_warning(0);
else if (version == '12.0(10)S')
  security_warning(0);
else if (version == '12.0(10)S0418')
  security_warning(0);
else if (version == '12.0(10)S0426')
  security_warning(0);
else if (version == '12.0(10)S1')
  security_warning(0);
else if (version == '12.0(10)S2')
  security_warning(0);
else if (version == '12.0(10)S3')
  security_warning(0);
else if (version == '12.0(10)S3a')
  security_warning(0);
else if (version == '12.0(10)S3b')
  security_warning(0);
else if (version == '12.0(10)S4')
  security_warning(0);
else if (version == '12.0(10)S5')
  security_warning(0);
else if (version == '12.0(10)S6')
  security_warning(0);
else if (version == '12.0(10)S7')
  security_warning(0);
else if (version == '12.0(10)S8')
  security_warning(0);
else if (version == '12.0(10)SC')
  security_warning(0);
else if (version == '12.0(10)SC1')
  security_warning(0);
else if (version == '12.0(10)SL')
  security_warning(0);
else if (version == '12.0(10)ST')
  security_warning(0);
else if (version == '12.0(10)ST1')
  security_warning(0);
else if (version == '12.0(10)ST2')
  security_warning(0);
else if (version == '12.0(10)SX')
  security_warning(0);
else if (version == '12.0(11)S')
  security_warning(0);
else if (version == '12.0(11)S1')
  security_warning(0);
else if (version == '12.0(11)S2')
  security_warning(0);
else if (version == '12.0(11)S3')
  security_warning(0);
else if (version == '12.0(11)S4')
  security_warning(0);
else if (version == '12.0(11)S5')
  security_warning(0);
else if (version == '12.0(11)S6')
  security_warning(0);
else if (version == '12.0(11)SC')
  security_warning(0);
else if (version == '12.0(11)SL')
  security_warning(0);
else if (version == '12.0(11)SL1')
  security_warning(0);
else if (version == '12.0(11)ST')
  security_warning(0);
else if (version == '12.0(11)ST1')
  security_warning(0);
else if (version == '12.0(11)ST2')
  security_warning(0);
else if (version == '12.0(11)ST3')
  security_warning(0);
else if (version == '12.0(11)ST4')
  security_warning(0);
else if (version == '12.0(12)S')
  security_warning(0);
else if (version == '12.0(12)S0830')
  security_warning(0);
else if (version == '12.0(12)S0912')
  security_warning(0);
else if (version == '12.0(12)S0916')
  security_warning(0);
else if (version == '12.0(12)S0918')
  security_warning(0);
else if (version == '12.0(12)S1')
  security_warning(0);
else if (version == '12.0(12)S2')
  security_warning(0);
else if (version == '12.0(12)S3')
  security_warning(0);
else if (version == '12.0(12)S4')
  security_warning(0);
else if (version == '12.0(12)SC')
  security_warning(0);
else if (version == '12.0(13)S')
  security_warning(0);
else if (version == '12.0(13)S1')
  security_warning(0);
else if (version == '12.0(13)S1016')
  security_warning(0);
else if (version == '12.0(13)S1022')
  security_warning(0);
else if (version == '12.0(13)S1023')
  security_warning(0);
else if (version == '12.0(13)S2')
  security_warning(0);
else if (version == '12.0(13)S2a')
  security_warning(0);
else if (version == '12.0(13)S3')
  security_warning(0);
else if (version == '12.0(13)S4')
  security_warning(0);
else if (version == '12.0(13)S5')
  security_warning(0);
else if (version == '12.0(13)S5a')
  security_warning(0);
else if (version == '12.0(13)S5b')
  security_warning(0);
else if (version == '12.0(13)S6')
  security_warning(0);
else if (version == '12.0(13)S7')
  security_warning(0);
else if (version == '12.0(13)S8')
  security_warning(0);
else if (version == '12.0(13)SC')
  security_warning(0);
else if (version == '12.0(14)S')
  security_warning(0);
else if (version == '12.0(14)S1')
  security_warning(0);
else if (version == '12.0(14)S1205')
  security_warning(0);
else if (version == '12.0(14)S1211')
  security_warning(0);
else if (version == '12.0(14)S1213')
  security_warning(0);
else if (version == '12.0(14)S1226')
  security_warning(0);
else if (version == '12.0(14)S2')
  security_warning(0);
else if (version == '12.0(14)S3')
  security_warning(0);
else if (version == '12.0(14)S4')
  security_warning(0);
else if (version == '12.0(14)S5')
  security_warning(0);
else if (version == '12.0(14)S6')
  security_warning(0);
else if (version == '12.0(14)S7')
  security_warning(0);
else if (version == '12.0(14)S8')
  security_warning(0);
else if (version == '12.0(14)SC')
  security_warning(0);
else if (version == '12.0(14)SL')
  security_warning(0);
else if (version == '12.0(14)SL1')
  security_warning(0);
else if (version == '12.0(14)ST')
  security_warning(0);
else if (version == '12.0(14)ST1')
  security_warning(0);
else if (version == '12.0(14)ST2')
  security_warning(0);
else if (version == '12.0(14)ST3')
  security_warning(0);
else if (version == '12.0(15)S')
  security_warning(0);
else if (version == '12.0(15)S0205')
  security_warning(0);
else if (version == '12.0(15)S0209')
  security_warning(0);
else if (version == '12.0(15)S0212')
  security_warning(0);
else if (version == '12.0(15)S0215')
  security_warning(0);
else if (version == '12.0(15)S0216')
  security_warning(0);
else if (version == '12.0(15)S1')
  security_warning(0);
else if (version == '12.0(15)S2')
  security_warning(0);
else if (version == '12.0(15)S3')
  security_warning(0);
else if (version == '12.0(15)S3a')
  security_warning(0);
else if (version == '12.0(15)S4')
  security_warning(0);
else if (version == '12.0(15)S5')
  security_warning(0);
else if (version == '12.0(15)S6')
  security_warning(0);
else if (version == '12.0(15)S7')
  security_warning(0);
else if (version == '12.0(15)SC')
  security_warning(0);
else if (version == '12.0(15)SC1')
  security_warning(0);
else if (version == '12.0(15)SL')
  security_warning(0);
else if (version == '12.0(16)S')
  security_warning(0);
else if (version == '12.0(16)S0416')
  security_warning(0);
else if (version == '12.0(16)S0422')
  security_warning(0);
else if (version == '12.0(16)S0425')
  security_warning(0);
else if (version == '12.0(16)S1')
  security_warning(0);
else if (version == '12.0(16)S10')
  security_warning(0);
else if (version == '12.0(16)S11')
  security_warning(0);
else if (version == '12.0(16)S12')
  security_warning(0);
else if (version == '12.0(16)S1a')
  security_warning(0);
else if (version == '12.0(16)S2')
  security_warning(0);
else if (version == '12.0(16)S3')
  security_warning(0);
else if (version == '12.0(16)S4')
  security_warning(0);
else if (version == '12.0(16)S4a')
  security_warning(0);
else if (version == '12.0(16)S5')
  security_warning(0);
else if (version == '12.0(16)S6')
  security_warning(0);
else if (version == '12.0(16)S7')
  security_warning(0);
else if (version == '12.0(16)S8')
  security_warning(0);
else if (version == '12.0(16)S8a')
  security_warning(0);
else if (version == '12.0(16)S9')
  security_warning(0);
else if (version == '12.0(16)SC')
  security_warning(0);
else if (version == '12.0(16)SC1')
  security_warning(0);
else if (version == '12.0(16)SC2')
  security_warning(0);
else if (version == '12.0(16)SC3')
  security_warning(0);
else if (version == '12.0(16)ST')
  security_warning(0);
else if (version == '12.0(16)ST1')
  security_warning(0);
else if (version == '12.0(17)S')
  security_warning(0);
else if (version == '12.0(17)S0620')
  security_warning(0);
else if (version == '12.0(17)S0621')
  security_warning(0);
else if (version == '12.0(17)S1')
  security_warning(0);
else if (version == '12.0(17)S2')
  security_warning(0);
else if (version == '12.0(17)S3')
  security_warning(0);
else if (version == '12.0(17)S4')
  security_warning(0);
else if (version == '12.0(17)S5')
  security_warning(0);
else if (version == '12.0(17)S6')
  security_warning(0);
else if (version == '12.0(17)S7')
  security_warning(0);
else if (version == '12.0(17)SL')
  security_warning(0);
else if (version == '12.0(17)SL1')
  security_warning(0);
else if (version == '12.0(17)SL2')
  security_warning(0);
else if (version == '12.0(17)SL3')
  security_warning(0);
else if (version == '12.0(17)SL4')
  security_warning(0);
else if (version == '12.0(17)SL5')
  security_warning(0);
else if (version == '12.0(17)SL6')
  security_warning(0);
else if (version == '12.0(17)SL7')
  security_warning(0);
else if (version == '12.0(17)SL8')
  security_warning(0);
else if (version == '12.0(17)SL9')
  security_warning(0);
else if (version == '12.0(17)ST')
  security_warning(0);
else if (version == '12.0(17)ST0622')
  security_warning(0);
else if (version == '12.0(17)ST071201')
  security_warning(0);
else if (version == '12.0(17)ST0717')
  security_warning(0);
else if (version == '12.0(17)ST0719')
  security_warning(0);
else if (version == '12.0(17)ST0726')
  security_warning(0);
else if (version == '12.0(17)ST1')
  security_warning(0);
else if (version == '12.0(17)ST10')
  security_warning(0);
else if (version == '12.0(17)ST2')
  security_warning(0);
else if (version == '12.0(17)ST3')
  security_warning(0);
else if (version == '12.0(17)ST4')
  security_warning(0);
else if (version == '12.0(17)ST5')
  security_warning(0);
else if (version == '12.0(17)ST6')
  security_warning(0);
else if (version == '12.0(17)ST7')
  security_warning(0);
else if (version == '12.0(17)ST8')
  security_warning(0);
else if (version == '12.0(17)ST9')
  security_warning(0);
else if (version == '12.0(18)S')
  security_warning(0);
else if (version == '12.0(18)S0814')
  security_warning(0);
else if (version == '12.0(18)S0906')
  security_warning(0);
else if (version == '12.0(18)S1')
  security_warning(0);
else if (version == '12.0(18)S2')
  security_warning(0);
else if (version == '12.0(18)S3')
  security_warning(0);
else if (version == '12.0(18)S4')
  security_warning(0);
else if (version == '12.0(18)S5')
  security_warning(0);
else if (version == '12.0(18)S5a')
  security_warning(0);
else if (version == '12.0(18)S6')
  security_warning(0);
else if (version == '12.0(18)S7')
  security_warning(0);
else if (version == '12.0(18)ST')
  security_warning(0);
else if (version == '12.0(18)ST1')
  security_warning(0);
else if (version == '12.0(19)S')
  security_warning(0);
else if (version == '12.0(19)S1')
  security_warning(0);
else if (version == '12.0(19)S1128')
  security_warning(0);
else if (version == '12.0(19)S2')
  security_warning(0);
else if (version == '12.0(19)S2a')
  security_warning(0);
else if (version == '12.0(19)S3')
  security_warning(0);
else if (version == '12.0(19)S4')
  security_warning(0);
else if (version == '12.0(19)SL')
  security_warning(0);
else if (version == '12.0(19)SL1')
  security_warning(0);
else if (version == '12.0(19)SL2')
  security_warning(0);
else if (version == '12.0(19)SL3')
  security_warning(0);
else if (version == '12.0(19)SL4')
  security_warning(0);
else if (version == '12.0(19)SP')
  security_warning(0);
else if (version == '12.0(19)ST')
  security_warning(0);
else if (version == '12.0(19)ST1')
  security_warning(0);
else if (version == '12.0(19)ST1114')
  security_warning(0);
else if (version == '12.0(19)ST1116')
  security_warning(0);
else if (version == '12.0(19)ST2')
  security_warning(0);
else if (version == '12.0(19)ST3')
  security_warning(0);
else if (version == '12.0(19)ST4')
  security_warning(0);
else if (version == '12.0(19)ST5')
  security_warning(0);
else if (version == '12.0(19)ST6')
  security_warning(0);
else if (version == '12.0(202)TEST')
  security_warning(0);
else if (version == '12.0(20)SP')
  security_warning(0);
else if (version == '12.0(20)SP1')
  security_warning(0);
else if (version == '12.0(20)SP2')
  security_warning(0);
else if (version == '12.0(20)ST')
  security_warning(0);
else if (version == '12.0(20)ST1')
  security_warning(0);
else if (version == '12.0(20)ST2')
  security_warning(0);
else if (version == '12.0(20)ST3')
  security_warning(0);
else if (version == '12.0(20)ST4')
  security_warning(0);
else if (version == '12.0(20)ST5')
  security_warning(0);
else if (version == '12.0(20)ST6')
  security_warning(0);
else if (version == '12.0(21)S')
  security_warning(0);
else if (version == '12.0(21)S0122')
  security_warning(0);
else if (version == '12.0(21)S0130')
  security_warning(0);
else if (version == '12.0(21)S0207')
  security_warning(0);
else if (version == '12.0(21)S0213')
  security_warning(0);
else if (version == '12.0(21)S1')
  security_warning(0);
else if (version == '12.0(21)S2')
  security_warning(0);
else if (version == '12.0(21)S3')
  security_warning(0);
else if (version == '12.0(21)S4')
  security_warning(0);
else if (version == '12.0(21)S4a')
  security_warning(0);
else if (version == '12.0(21)S5')
  security_warning(0);
else if (version == '12.0(21)S5a')
  security_warning(0);
else if (version == '12.0(21)S6')
  security_warning(0);
else if (version == '12.0(21)S6a')
  security_warning(0);
else if (version == '12.0(21)S7')
  security_warning(0);
else if (version == '12.0(21)S8')
  security_warning(0);
else if (version == '12.0(21)SP')
  security_warning(0);
else if (version == '12.0(21)SP0722')
  security_warning(0);
else if (version == '12.0(21)SP0726')
  security_warning(0);
else if (version == '12.0(21)SP1')
  security_warning(0);
else if (version == '12.0(21)SP2')
  security_warning(0);
else if (version == '12.0(21)SP3')
  security_warning(0);
else if (version == '12.0(21)SP4')
  security_warning(0);
else if (version == '12.0(21)ST')
  security_warning(0);
else if (version == '12.0(21)ST0318')
  security_warning(0);
else if (version == '12.0(21)ST0321')
  security_warning(0);
else if (version == '12.0(21)ST0326')
  security_warning(0);
else if (version == '12.0(21)ST1')
  security_warning(0);
else if (version == '12.0(21)ST2')
  security_warning(0);
else if (version == '12.0(21)ST2a')
  security_warning(0);
else if (version == '12.0(21)ST2b')
  security_warning(0);
else if (version == '12.0(21)ST3')
  security_warning(0);
else if (version == '12.0(21)ST3a')
  security_warning(0);
else if (version == '12.0(21)ST4')
  security_warning(0);
else if (version == '12.0(21)ST5')
  security_warning(0);
else if (version == '12.0(21)ST6')
  security_warning(0);
else if (version == '12.0(21)ST6a')
  security_warning(0);
else if (version == '12.0(21)ST7')
  security_warning(0);
else if (version == '12.0(21)SX')
  security_warning(0);
else if (version == '12.0(21)SX1')
  security_warning(0);
else if (version == '12.0(21)SZ')
  security_warning(0);
else if (version == '12.0(22)S')
  security_warning(0);
else if (version == '12.0(22)S0815')
  security_warning(0);
else if (version == '12.0(22)S0828')
  security_warning(0);
else if (version == '12.0(22)S0903')
  security_warning(0);
else if (version == '12.0(22)S0911')
  security_warning(0);
else if (version == '12.0(22)S0914')
  security_warning(0);
else if (version == '12.0(22)S1')
  security_warning(0);
else if (version == '12.0(22)S2')
  security_warning(0);
else if (version == '12.0(22)S2a')
  security_warning(0);
else if (version == '12.0(22)S2b')
  security_warning(0);
else if (version == '12.0(22)S2c')
  security_warning(0);
else if (version == '12.0(22)S2d')
  security_warning(0);
else if (version == '12.0(22)S2e')
  security_warning(0);
else if (version == '12.0(22)S3')
  security_warning(0);
else if (version == '12.0(22)S3a')
  security_warning(0);
else if (version == '12.0(22)S3b')
  security_warning(0);
else if (version == '12.0(22)S3c')
  security_warning(0);
else if (version == '12.0(22)S4')
  security_warning(0);
else if (version == '12.0(22)S4a')
  security_warning(0);
else if (version == '12.0(22)S5')
  security_warning(0);
else if (version == '12.0(22)S5a')
  security_warning(0);
else if (version == '12.0(22)S6')
  security_warning(0);
else if (version == '12.0(22)SY')
  security_warning(0);
else if (version == '12.0(23)S')
  security_warning(0);
else if (version == '12.0(23)S012')
  security_warning(0);
else if (version == '12.0(23)S1')
  security_warning(0);
else if (version == '12.0(23)S1105')
  security_warning(0);
else if (version == '12.0(23)S1105a')
  security_warning(0);
else if (version == '12.0(23)S1106')
  security_warning(0);
else if (version == '12.0(23)S1118')
  security_warning(0);
else if (version == '12.0(23)S1123')
  security_warning(0);
else if (version == '12.0(23)S2')
  security_warning(0);
else if (version == '12.0(23)S2a')
  security_warning(0);
else if (version == '12.0(23)S2b')
  security_warning(0);
else if (version == '12.0(23)S3')
  security_warning(0);
else if (version == '12.0(23)S3a')
  security_warning(0);
else if (version == '12.0(23)S3b')
  security_warning(0);
else if (version == '12.0(23)S3c')
  security_warning(0);
else if (version == '12.0(23)S4')
  security_warning(0);
else if (version == '12.0(23)S5')
  security_warning(0);
else if (version == '12.0(23)S6')
  security_warning(0);
else if (version == '12.0(23)S6a')
  security_warning(0);
else if (version == '12.0(23)SX')
  security_warning(0);
else if (version == '12.0(23)SX1')
  security_warning(0);
else if (version == '12.0(23)SX2')
  security_warning(0);
else if (version == '12.0(23)SX3')
  security_warning(0);
else if (version == '12.0(23)SX4')
  security_warning(0);
else if (version == '12.0(23)SX5')
  security_warning(0);
else if (version == '12.0(23)SZ')
  security_warning(0);
else if (version == '12.0(23)SZ0314')
  security_warning(0);
else if (version == '12.0(23)SZ1213')
  security_warning(0);
else if (version == '12.0(23)SZ2')
  security_warning(0);
else if (version == '12.0(23)SZ3')
  security_warning(0);
else if (version == '12.0(24)S')
  security_warning(0);
else if (version == '12.0(24)S0303')
  security_warning(0);
else if (version == '12.0(24)S0310')
  security_warning(0);
else if (version == '12.0(24)S0323')
  security_warning(0);
else if (version == '12.0(24)S1')
  security_warning(0);
else if (version == '12.0(24)S2')
  security_warning(0);
else if (version == '12.0(24)S2a')
  security_warning(0);
else if (version == '12.0(24)S2b')
  security_warning(0);
else if (version == '12.0(24)S2c')
  security_warning(0);
else if (version == '12.0(24)S3')
  security_warning(0);
else if (version == '12.0(24)S4')
  security_warning(0);
else if (version == '12.0(24)S4a')
  security_warning(0);
else if (version == '12.0(24)S4b')
  security_warning(0);
else if (version == '12.0(24)S5')
  security_warning(0);
else if (version == '12.0(24)S5a')
  security_warning(0);
else if (version == '12.0(24)S6')
  security_warning(0);
else if (version == '12.0(24)S6a')
  security_warning(0);
else if (version == '12.0(24)SX')
  security_warning(0);
else if (version == '12.0(25)S')
  security_warning(0);
else if (version == '12.0(25)S0611')
  security_warning(0);
else if (version == '12.0(25)S0616')
  security_warning(0);
else if (version == '12.0(25)S0627')
  security_warning(0);
else if (version == '12.0(25)S1')
  security_warning(0);
else if (version == '12.0(25)S1a')
  security_warning(0);
else if (version == '12.0(25)S1b')
  security_warning(0);
else if (version == '12.0(25)S1c')
  security_warning(0);
else if (version == '12.0(25)S1d')
  security_warning(0);
else if (version == '12.0(25)S2')
  security_warning(0);
else if (version == '12.0(25)S3')
  security_warning(0);
else if (version == '12.0(25)S4')
  security_warning(0);
else if (version == '12.0(25)S4a')
  security_warning(0);
else if (version == '12.0(25)S4b')
  security_warning(0);
else if (version == '12.0(25)S4c')
  security_warning(0);
else if (version == '12.0(25)S4d')
  security_warning(0);
else if (version == '12.0(25)S5')
  security_warning(0);
else if (version == '12.0(25)S6')
  security_warning(0);
else if (version == '12.0(25)SX')
  security_warning(0);
else if (version == '12.0(25)SX1')
  security_warning(0);
else if (version == '12.0(25)SX10')
  security_warning(0);
else if (version == '12.0(25)SX2')
  security_warning(0);
else if (version == '12.0(25)SX3')
  security_warning(0);
else if (version == '12.0(25)SX4')
  security_warning(0);
else if (version == '12.0(25)SX5')
  security_warning(0);
else if (version == '12.0(25)SX6')
  security_warning(0);
else if (version == '12.0(25)SX6a')
  security_warning(0);
else if (version == '12.0(25)SX6b')
  security_warning(0);
else if (version == '12.0(25)SX6c')
  security_warning(0);
else if (version == '12.0(25)SX6d')
  security_warning(0);
else if (version == '12.0(25)SX6e')
  security_warning(0);
else if (version == '12.0(25)SX6f')
  security_warning(0);
else if (version == '12.0(25)SX6g')
  security_warning(0);
else if (version == '12.0(25)SX7')
  security_warning(0);
else if (version == '12.0(25)SX8')
  security_warning(0);
else if (version == '12.0(25)SX9')
  security_warning(0);
else if (version == '12.0(26)S')
  security_warning(0);
else if (version == '12.0(26)S0223')
  security_warning(0);
else if (version == '12.0(26)S1')
  security_warning(0);
else if (version == '12.0(26)S1014')
  security_warning(0);
else if (version == '12.0(26)S1110')
  security_warning(0);
else if (version == '12.0(26)S1201')
  security_warning(0);
else if (version == '12.0(26)S2')
  security_warning(0);
else if (version == '12.0(26)S2a')
  security_warning(0);
else if (version == '12.0(26)S2b')
  security_warning(0);
else if (version == '12.0(26)S2c')
  security_warning(0);
else if (version == '12.0(26)S3')
  security_warning(0);
else if (version == '12.0(26)S3a')
  security_warning(0);
else if (version == '12.0(26)S4')
  security_warning(0);
else if (version == '12.0(26)S4a')
  security_warning(0);
else if (version == '12.0(26)S4b')
  security_warning(0);
else if (version == '12.0(26)S4c')
  security_warning(0);
else if (version == '12.0(26)S5')
  security_warning(0);
else if (version == '12.0(26)S5a')
  security_warning(0);
else if (version == '12.0(26)S5b')
  security_warning(0);
else if (version == '12.0(26)S6')
  security_warning(0);
else if (version == '12.0(26)SZ')
  security_warning(0);
else if (version == '12.0(26)SZ0813')
  security_warning(0);
else if (version == '12.0(26)SZ0822')
  security_warning(0);
else if (version == '12.0(27r)S1')
  security_warning(0);
else if (version == '12.0(27r)S4')
  security_warning(0);
else if (version == '12.0(27)S')
  security_warning(0);
else if (version == '12.0(27)S0205')
  security_warning(0);
else if (version == '12.0(27)S0712')
  security_warning(0);
else if (version == '12.0(27)S0730')
  security_warning(0);
else if (version == '12.0(27)S1')
  security_warning(0);
else if (version == '12.0(27)S2')
  security_warning(0);
else if (version == '12.0(27)S2a')
  security_warning(0);
else if (version == '12.0(27)S2b')
  security_warning(0);
else if (version == '12.0(27)S2c')
  security_warning(0);
else if (version == '12.0(27)S2d')
  security_warning(0);
else if (version == '12.0(27)S3')
  security_warning(0);
else if (version == '12.0(27)S3a')
  security_warning(0);
else if (version == '12.0(27)S3b')
  security_warning(0);
else if (version == '12.0(27)S3c')
  security_warning(0);
else if (version == '12.0(27)S3d')
  security_warning(0);
else if (version == '12.0(27)S4')
  security_warning(0);
else if (version == '12.0(27)S4a')
  security_warning(0);
else if (version == '12.0(27)S4b')
  security_warning(0);
else if (version == '12.0(27)S4c')
  security_warning(0);
else if (version == '12.0(27)S5')
  security_warning(0);
else if (version == '12.0(27)S5a')
  security_warning(0);
else if (version == '12.0(27)S5b')
  security_warning(0);
else if (version == '12.0(27)S5c')
  security_warning(0);
else if (version == '12.0(27)S5d')
  security_warning(0);
else if (version == '12.0(27)SV')
  security_warning(0);
else if (version == '12.0(27)SV1')
  security_warning(0);
else if (version == '12.0(27)SV2')
  security_warning(0);
else if (version == '12.0(27)SV3')
  security_warning(0);
else if (version == '12.0(27)SV4')
  security_warning(0);
else if (version == '12.0(27)SW0307')
  security_warning(0);
else if (version == '12.0(27)SY')
  security_warning(0);
else if (version == '12.0(27)SY0216')
  security_warning(0);
else if (version == '12.0(27)SY0218')
  security_warning(0);
else if (version == '12.0(27)SY0318')
  security_warning(0);
else if (version == '12.0(27)SZ')
  security_warning(0);
else if (version == '12.0(28)S')
  security_warning(0);
else if (version == '12.0(28)S0623')
  security_warning(0);
else if (version == '12.0(28)S0731')
  security_warning(0);
else if (version == '12.0(28)S0805')
  security_warning(0);
else if (version == '12.0(28)S0823')
  security_warning(0);
else if (version == '12.0(28)S0824')
  security_warning(0);
else if (version == '12.0(28)S1')
  security_warning(0);
else if (version == '12.0(28)S1a')
  security_warning(0);
else if (version == '12.0(28)S2')
  security_warning(0);
else if (version == '12.0(28)S2a')
  security_warning(0);
else if (version == '12.0(28)S3')
  security_warning(0);
else if (version == '12.0(28)S4')
  security_warning(0);
else if (version == '12.0(28)S4a')
  security_warning(0);
else if (version == '12.0(28)S4b')
  security_warning(0);
else if (version == '12.0(28)S4c')
  security_warning(0);
else if (version == '12.0(28)S5')
  security_warning(0);
else if (version == '12.0(28)S5a')
  security_warning(0);
else if (version == '12.0(28)S5b')
  security_warning(0);
else if (version == '12.0(28)S5c')
  security_warning(0);
else if (version == '12.0(28)S5d')
  security_warning(0);
else if (version == '12.0(28)S6')
  security_warning(0);
else if (version == '12.0(28)S6a')
  security_warning(0);
else if (version == '12.0(28)SV')
  security_warning(0);
else if (version == '12.0(28)SW')
  security_warning(0);
else if (version == '12.0(28)SW1')
  security_warning(0);
else if (version == '12.0(29)S')
  security_warning(0);
else if (version == '12.0(29)S1')
  security_warning(0);
else if (version == '12.0(29)S1103')
  security_warning(0);
else if (version == '12.0(30)S')
  security_warning(0);
else if (version == '12.0(30)S0113')
  security_warning(0);
else if (version == '12.0(30)S0204')
  security_warning(0);
else if (version == '12.0(30)S0205')
  security_warning(0);
else if (version == '12.0(30)S0206')
  security_warning(0);
else if (version == '12.0(30)S0210')
  security_warning(0);
else if (version == '12.0(30)S0227')
  security_warning(0);
else if (version == '12.0(30)S0303')
  security_warning(0);
else if (version == '12.0(30)S1')
  security_warning(0);
else if (version == '12.0(30)S1229')
  security_warning(0);
else if (version == '12.0(30)S2')
  security_warning(0);
else if (version == '12.0(30)S2a')
  security_warning(0);
else if (version == '12.0(30)S2m')
  security_warning(0);
else if (version == '12.0(30)S2n')
  security_warning(0);
else if (version == '12.0(30)S3')
  security_warning(0);
else if (version == '12.0(30)S3a')
  security_warning(0);
else if (version == '12.0(30)S3b')
  security_warning(0);
else if (version == '12.0(30)S3c')
  security_warning(0);
else if (version == '12.0(30)S3d')
  security_warning(0);
else if (version == '12.0(30)S3s')
  security_warning(0);
else if (version == '12.0(30)S3t')
  security_warning(0);
else if (version == '12.0(30)S4')
  security_warning(0);
else if (version == '12.0(30)S4a')
  security_warning(0);
else if (version == '12.0(30)S4b')
  security_warning(0);
else if (version == '12.0(30)S5')
  security_warning(0);
else if (version == '12.0(30)SV1')
  security_warning(0);
else if (version == '12.0(30)SW')
  security_warning(0);
else if (version == '12.0(30)SX')
  security_warning(0);
else if (version == '12.0(30)SZ')
  security_warning(0);
else if (version == '12.0(30)TST')
  security_warning(0);
else if (version == '12.0(30)TST1')
  security_warning(0);
else if (version == '12.0(31)S')
  security_warning(0);
else if (version == '12.0(31)S0518')
  security_warning(0);
else if (version == '12.0(31)S0519')
  security_warning(0);
else if (version == '12.0(31)S0520')
  security_warning(0);
else if (version == '12.0(31)S0a')
  security_warning(0);
else if (version == '12.0(31)S0b')
  security_warning(0);
else if (version == '12.0(31)S1')
  security_warning(0);
else if (version == '12.0(31)S1a')
  security_warning(0);
else if (version == '12.0(31)S1b')
  security_warning(0);
else if (version == '12.0(31)S1c')
  security_warning(0);
else if (version == '12.0(31)S1d')
  security_warning(0);
else if (version == '12.0(31)S2')
  security_warning(0);
else if (version == '12.0(31)S2a')
  security_warning(0);
else if (version == '12.0(31)S2b')
  security_warning(0);
else if (version == '12.0(31)S2c')
  security_warning(0);
else if (version == '12.0(31)S2d')
  security_warning(0);
else if (version == '12.0(31)S2s')
  security_warning(0);
else if (version == '12.0(31)S2t')
  security_warning(0);
else if (version == '12.0(31)S2u')
  security_warning(0);
else if (version == '12.0(31)S2v')
  security_warning(0);
else if (version == '12.0(31)S3')
  security_warning(0);
else if (version == '12.0(31)S3a')
  security_warning(0);
else if (version == '12.0(31)S3b')
  security_warning(0);
else if (version == '12.0(31)S3c')
  security_warning(0);
else if (version == '12.0(31)S4')
  security_warning(0);
else if (version == '12.0(31)S4a')
  security_warning(0);
else if (version == '12.0(31)S4b')
  security_warning(0);
else if (version == '12.0(31)S4c')
  security_warning(0);
else if (version == '12.0(31)S5')
  security_warning(0);
else if (version == '12.0(31)S5a')
  security_warning(0);
else if (version == '12.0(31)SV')
  security_warning(0);
else if (version == '12.0(31)SV1')
  security_warning(0);
else if (version == '12.0(31)SZ2')
  security_warning(0);
else if (version == '12.0(32)S')
  security_warning(0);
else if (version == '12.0(32)S1')
  security_warning(0);
else if (version == '12.0(32)S1a')
  security_warning(0);
else if (version == '12.0(32)S1b')
  security_warning(0);
else if (version == '12.0(32)S2')
  security_warning(0);
else if (version == '12.0(3)S')
  security_warning(0);
else if (version == '12.0(4)S')
  security_warning(0);
else if (version == '12.0(5)S')
  security_warning(0);
else if (version == '12.0(5)S0714')
  security_warning(0);
else if (version == '12.0(5)S0722')
  security_warning(0);
else if (version == '12.0(5)S0723')
  security_warning(0);
else if (version == '12.0(5)S0726')
  security_warning(0);
else if (version == '12.0(5)S0727')
  security_warning(0);
else if (version == '12.0(6)S')
  security_warning(0);
else if (version == '12.0(6)S1')
  security_warning(0);
else if (version == '12.0(6)S2')
  security_warning(0);
else if (version == '12.0(6)SC')
  security_warning(0);
else if (version == '12.0(7)S')
  security_warning(0);
else if (version == '12.0(7)S1')
  security_warning(0);
else if (version == '12.0(7)S1110')
  security_warning(0);
else if (version == '12.0(7)S1113')
  security_warning(0);
else if (version == '12.0(7)S1116')
  security_warning(0);
else if (version == '12.0(7)S1123')
  security_warning(0);
else if (version == '12.0(7)SC')
  security_warning(0);
else if (version == '12.0(8)S')
  security_warning(0);
else if (version == '12.0(8)S0208')
  security_warning(0);
else if (version == '12.0(8)S0412')
  security_warning(0);
else if (version == '12.0(8)S1')
  security_warning(0);
else if (version == '12.0(8)SC')
  security_warning(0);
else if (version == '12.0(8)SC1')
  security_warning(0);
else if (version == '12.0(9r)SL')
  security_warning(0);
else if (version == '12.0(9r)SL1')
  security_warning(0);
else if (version == '12.0(9r)SL2')
  security_warning(0);
else if (version == '12.0(9)S')
  security_warning(0);
else if (version == '12.0(9)S0310')
  security_warning(0);
else if (version == '12.0(9)S1')
  security_warning(0);
else if (version == '12.0(9)S2')
  security_warning(0);
else if (version == '12.0(9)S3')
  security_warning(0);
else if (version == '12.0(9)S4')
  security_warning(0);
else if (version == '12.0(9)S5')
  security_warning(0);
else if (version == '12.0(9)S6')
  security_warning(0);
else if (version == '12.0(9)S7')
  security_warning(0);
else if (version == '12.0(9)S8')
  security_warning(0);
else if (version == '12.0(9)SC')
  security_warning(0);
else if (version == '12.0(9)SL')
  security_warning(0);
else if (version == '12.0(9)SL1')
  security_warning(0);
else if (version == '12.0(9)SL2')
  security_warning(0);
else if (version == '12.0(9)ST')
  security_warning(0);
else if (version == '12.2(1)')
  security_warning(0);
else if (version == '12.2(10)')
  security_warning(0);
else if (version == '12.2(10a)')
  security_warning(0);
else if (version == '12.2(10b)')
  security_warning(0);
else if (version == '12.2(10c)')
  security_warning(0);
else if (version == '12.2(10d)')
  security_warning(0);
else if (version == '12.2(10)DA')
  security_warning(0);
else if (version == '12.2(10)DA1')
  security_warning(0);
else if (version == '12.2(10)DA2')
  security_warning(0);
else if (version == '12.2(10)DA3')
  security_warning(0);
else if (version == '12.2(10)DA4')
  security_warning(0);
else if (version == '12.2(10)DA5')
  security_warning(0);
else if (version == '12.2(10e)')
  security_warning(0);
else if (version == '12.2(10f)')
  security_warning(0);
else if (version == '12.2(10g)')
  security_warning(0);
else if (version == '12.2(10r)')
  security_warning(0);
else if (version == '12.2(11)BC1')
  security_warning(0);
else if (version == '12.2(11)BC1a')
  security_warning(0);
else if (version == '12.2(11)BC1b')
  security_warning(0);
else if (version == '12.2(11)BC2')
  security_warning(0);
else if (version == '12.2(11)BC2a')
  security_warning(0);
else if (version == '12.2(11)BC3')
  security_warning(0);
else if (version == '12.2(11)BC3a')
  security_warning(0);
else if (version == '12.2(11)BC3b')
  security_warning(0);
else if (version == '12.2(11)BC3c')
  security_warning(0);
else if (version == '12.2(11)BC3d')
  security_warning(0);
else if (version == '12.2(11)CX')
  security_warning(0);
else if (version == '12.2(11)CX1')
  security_warning(0);
else if (version == '12.2(11)CY')
  security_warning(0);
else if (version == '12.2(11)JA')
  security_warning(0);
else if (version == '12.2(11)JA1')
  security_warning(0);
else if (version == '12.2(11)JA2')
  security_warning(0);
else if (version == '12.2(11)JA3')
  security_warning(0);
else if (version == '12.2(11r)T')
  security_warning(0);
else if (version == '12.2(11r)T1')
  security_warning(0);
else if (version == '12.2(11r)YS1')
  security_warning(0);
else if (version == '12.2(11)S')
  security_warning(0);
else if (version == '12.2(11)S1')
  security_warning(0);
else if (version == '12.2(11)S2')
  security_warning(0);
else if (version == '12.2(11)S3')
  security_warning(0);
else if (version == '12.2(11)T')
  security_warning(0);
else if (version == '12.2(11)T1')
  security_warning(0);
else if (version == '12.2(11)T10')
  security_warning(0);
else if (version == '12.2(11)T11')
  security_warning(0);
else if (version == '12.2(11)T2')
  security_warning(0);
else if (version == '12.2(11)T3')
  security_warning(0);
else if (version == '12.2(11)T4')
  security_warning(0);
else if (version == '12.2(11)T5')
  security_warning(0);
else if (version == '12.2(11)T6')
  security_warning(0);
else if (version == '12.2(11)T7')
  security_warning(0);
else if (version == '12.2(11)T8')
  security_warning(0);
else if (version == '12.2(11)T9')
  security_warning(0);
else if (version == '12.2(11)YP1')
  security_warning(0);
else if (version == '12.2(11)YP2')
  security_warning(0);
else if (version == '12.2(11)YP3')
  security_warning(0);
else if (version == '12.2(11)YP4')
  security_warning(0);
else if (version == '12.2(11)YP5')
  security_warning(0);
else if (version == '12.2(11)YS021223')
  security_warning(0);
else if (version == '12.2(11)ZC')
  security_warning(0);
else if (version == '12.2(1a)')
  security_warning(0);
else if (version == '12.2(1a)XC')
  security_warning(0);
else if (version == '12.2(1a)XC1')
  security_warning(0);
else if (version == '12.2(1a)XC2')
  security_warning(0);
else if (version == '12.2(1a)XC3')
  security_warning(0);
else if (version == '12.2(1a)XC4')
  security_warning(0);
else if (version == '12.2(1a)XC5')
  security_warning(0);
else if (version == '12.2(1b)')
  security_warning(0);
else if (version == '12.2(1b)DA')
  security_warning(0);
else if (version == '12.2(1b)DA1')
  security_warning(0);
else if (version == '12.2(1c)')
  security_warning(0);
else if (version == '12.2(1d)')
  security_warning(0);
else if (version == '12.2(1)DX')
  security_warning(0);
else if (version == '12.2(1)DX1')
  security_warning(0);
else if (version == '12.2(1)MB1')
  security_warning(0);
else if (version == '12.2(1r)')
  security_warning(0);
else if (version == '12.2(1r)DD')
  security_warning(0);
else if (version == '12.2(1r)DD1')
  security_warning(0);
else if (version == '12.2(1r)T')
  security_warning(0);
else if (version == '12.2(1r)T1')
  security_warning(0);
else if (version == '12.2(1r)XA')
  security_warning(0);
else if (version == '12.2(1r)XE')
  security_warning(0);
else if (version == '12.2(1r)XE1')
  security_warning(0);
else if (version == '12.2(1r)XE2')
  security_warning(0);
else if (version == '12.2(1)XD')
  security_warning(0);
else if (version == '12.2(1)XD1')
  security_warning(0);
else if (version == '12.2(1)XD2')
  security_warning(0);
else if (version == '12.2(1)XD3')
  security_warning(0);
else if (version == '12.2(1)XD4')
  security_warning(0);
else if (version == '12.2(1)XE')
  security_warning(0);
else if (version == '12.2(1)XE1')
  security_warning(0);
else if (version == '12.2(1)XE2')
  security_warning(0);
else if (version == '12.2(1)XS')
  security_warning(0);
else if (version == '12.2(1)XS1')
  security_warning(0);
else if (version == '12.2(1)XS1a')
  security_warning(0);
else if (version == '12.2(1)XS2')
  security_warning(0);
else if (version == '12.2(2)BX')
  security_warning(0);
else if (version == '12.2(2)BX1')
  security_warning(0);
else if (version == '12.2(2)BX2')
  security_warning(0);
else if (version == '12.2(2)DD')
  security_warning(0);
else if (version == '12.2(2)DD1')
  security_warning(0);
else if (version == '12.2(2)DD2')
  security_warning(0);
else if (version == '12.2(2)DD3')
  security_warning(0);
else if (version == '12.2(2)DD4')
  security_warning(0);
else if (version == '12.2(2)DX')
  security_warning(0);
else if (version == '12.2(2)DX1')
  security_warning(0);
else if (version == '12.2(2)DX2')
  security_warning(0);
else if (version == '12.2(2)DX3')
  security_warning(0);
else if (version == '12.2(2r)')
  security_warning(0);
else if (version == '12.2(2r)DD')
  security_warning(0);
else if (version == '12.2(2r)T2')
  security_warning(0);
else if (version == '12.2(2r)XA')
  security_warning(0);
else if (version == '12.2(2r)XB')
  security_warning(0);
else if (version == '12.2(2r)XB5')
  security_warning(0);
else if (version == '12.2(2r)XT')
  security_warning(0);
else if (version == '12.2(2)T')
  security_warning(0);
else if (version == '12.2(2)T1')
  security_warning(0);
else if (version == '12.2(2)T2')
  security_warning(0);
else if (version == '12.2(2)T3')
  security_warning(0);
else if (version == '12.2(2)T4')
  security_warning(0);
else if (version == '12.2(2)XA')
  security_warning(0);
else if (version == '12.2(2)XA1')
  security_warning(0);
else if (version == '12.2(2)XA2')
  security_warning(0);
else if (version == '12.2(2)XA3')
  security_warning(0);
else if (version == '12.2(2)XA4')
  security_warning(0);
else if (version == '12.2(2)XA5')
  security_warning(0);
else if (version == '12.2(2)XB')
  security_warning(0);
else if (version == '12.2(2)XB1')
  security_warning(0);
else if (version == '12.2(2)XB10')
  security_warning(0);
else if (version == '12.2(2)XB11')
  security_warning(0);
else if (version == '12.2(2)XB12')
  security_warning(0);
else if (version == '12.2(2)XB14')
  security_warning(0);
else if (version == '12.2(2)XB15')
  security_warning(0);
else if (version == '12.2(2)XB16')
  security_warning(0);
else if (version == '12.2(2)XB17')
  security_warning(0);
else if (version == '12.2(2)XB18')
  security_warning(0);
else if (version == '12.2(2)XB2')
  security_warning(0);
else if (version == '12.2(2)XB3')
  security_warning(0);
else if (version == '12.2(2)XB4')
  security_warning(0);
else if (version == '12.2(2)XB4b')
  security_warning(0);
else if (version == '12.2(2)XB5')
  security_warning(0);
else if (version == '12.2(2)XB6')
  security_warning(0);
else if (version == '12.2(2)XB6a')
  security_warning(0);
else if (version == '12.2(2)XB6b')
  security_warning(0);
else if (version == '12.2(2)XB6c')
  security_warning(0);
else if (version == '12.2(2)XB6d')
  security_warning(0);
else if (version == '12.2(2)XB7')
  security_warning(0);
else if (version == '12.2(2)XB8')
  security_warning(0);
else if (version == '12.2(2)XB9')
  security_warning(0);
else if (version == '12.2(2)XC')
  security_warning(0);
else if (version == '12.2(2)XC1')
  security_warning(0);
else if (version == '12.2(2)XC2')
  security_warning(0);
else if (version == '12.2(2)XC3')
  security_warning(0);
else if (version == '12.2(2)XC4')
  security_warning(0);
else if (version == '12.2(2)XC5')
  security_warning(0);
else if (version == '12.2(2)XC6')
  security_warning(0);
else if (version == '12.2(2)XC7')
  security_warning(0);
else if (version == '12.2(2)XF')
  security_warning(0);
else if (version == '12.2(2)XF1')
  security_warning(0);
else if (version == '12.2(2)XF2')
  security_warning(0);
else if (version == '12.2(2)XG')
  security_warning(0);
else if (version == '12.2(2)XG1')
  security_warning(0);
else if (version == '12.2(2)XH')
  security_warning(0);
else if (version == '12.2(2)XH1')
  security_warning(0);
else if (version == '12.2(2)XH2')
  security_warning(0);
else if (version == '12.2(2)XI')
  security_warning(0);
else if (version == '12.2(2)XI1')
  security_warning(0);
else if (version == '12.2(2)XI2')
  security_warning(0);
else if (version == '12.2(2)XJ')
  security_warning(0);
else if (version == '12.2(2)XK')
  security_warning(0);
else if (version == '12.2(2)XK1')
  security_warning(0);
else if (version == '12.2(2)XK2')
  security_warning(0);
else if (version == '12.2(2)XK3')
  security_warning(0);
else if (version == '12.2(2)XN')
  security_warning(0);
else if (version == '12.2(2)XQ')
  security_warning(0);
else if (version == '12.2(2)XQ1')
  security_warning(0);
else if (version == '12.2(2)XR')
  security_warning(0);
else if (version == '12.2(2)XT')
  security_warning(0);
else if (version == '12.2(2)XT1')
  security_warning(0);
else if (version == '12.2(2)XT2')
  security_warning(0);
else if (version == '12.2(2)XT3')
  security_warning(0);
else if (version == '12.2(2)XU')
  security_warning(0);
else if (version == '12.2(2)XU1')
  security_warning(0);
else if (version == '12.2(2)XU2')
  security_warning(0);
else if (version == '12.2(2)XU3')
  security_warning(0);
else if (version == '12.2(2)XU4')
  security_warning(0);
else if (version == '12.2(2)YC')
  security_warning(0);
else if (version == '12.2(2)YC1')
  security_warning(0);
else if (version == '12.2(2)YC2')
  security_warning(0);
else if (version == '12.2(2)YC3')
  security_warning(0);
else if (version == '12.2(2)YK')
  security_warning(0);
else if (version == '12.2(2)YK1')
  security_warning(0);
else if (version == '12.2(3)')
  security_warning(0);
else if (version == '12.2(3a)')
  security_warning(0);
else if (version == '12.2(3b)')
  security_warning(0);
else if (version == '12.2(3c)')
  security_warning(0);
else if (version == '12.2(3d)')
  security_warning(0);
else if (version == '12.2(3e)')
  security_warning(0);
else if (version == '12.2(3f)')
  security_warning(0);
else if (version == '12.2(3g)')
  security_warning(0);
else if (version == '12.2(4)B')
  security_warning(0);
else if (version == '12.2(4)B1')
  security_warning(0);
else if (version == '12.2(4)B2')
  security_warning(0);
else if (version == '12.2(4)B3')
  security_warning(0);
else if (version == '12.2(4)B4')
  security_warning(0);
else if (version == '12.2(4)B5')
  security_warning(0);
else if (version == '12.2(4)B6')
  security_warning(0);
else if (version == '12.2(4)B7')
  security_warning(0);
else if (version == '12.2(4)B7a')
  security_warning(0);
else if (version == '12.2(4)B8')
  security_warning(0);
else if (version == '12.2(4)BC1')
  security_warning(0);
else if (version == '12.2(4)BC1a')
  security_warning(0);
else if (version == '12.2(4)BC1b')
  security_warning(0);
else if (version == '12.2(4)BW')
  security_warning(0);
else if (version == '12.2(4)BW1')
  security_warning(0);
else if (version == '12.2(4)BW1a')
  security_warning(0);
else if (version == '12.2(4)BW2')
  security_warning(0);
else if (version == '12.2(4)BX')
  security_warning(0);
else if (version == '12.2(4)BX1')
  security_warning(0);
else if (version == '12.2(4)BX1a')
  security_warning(0);
else if (version == '12.2(4)BX1b')
  security_warning(0);
else if (version == '12.2(4)BX1c')
  security_warning(0);
else if (version == '12.2(4)BX1d')
  security_warning(0);
else if (version == '12.2(4)BX2')
  security_warning(0);
else if (version == '12.2(4)BY')
  security_warning(0);
else if (version == '12.2(4)BY1')
  security_warning(0);
else if (version == '12.2(4)JA')
  security_warning(0);
else if (version == '12.2(4)JA1')
  security_warning(0);
else if (version == '12.2(4)MB1')
  security_warning(0);
else if (version == '12.2(4)MB10')
  security_warning(0);
else if (version == '12.2(4)MB11')
  security_warning(0);
else if (version == '12.2(4)MB12')
  security_warning(0);
else if (version == '12.2(4)MB13')
  security_warning(0);
else if (version == '12.2(4)MB13a')
  security_warning(0);
else if (version == '12.2(4)MB13b')
  security_warning(0);
else if (version == '12.2(4)MB13c')
  security_warning(0);
else if (version == '12.2(4)MB2')
  security_warning(0);
else if (version == '12.2(4)MB3')
  security_warning(0);
else if (version == '12.2(4)MB4')
  security_warning(0);
else if (version == '12.2(4)MB5')
  security_warning(0);
else if (version == '12.2(4)MB6')
  security_warning(0);
else if (version == '12.2(4)MB7')
  security_warning(0);
else if (version == '12.2(4)MB8')
  security_warning(0);
else if (version == '12.2(4)MB9')
  security_warning(0);
else if (version == '12.2(4)MB9a')
  security_warning(0);
else if (version == '12.2(4)MX')
  security_warning(0);
else if (version == '12.2(4)MX1')
  security_warning(0);
else if (version == '12.2(4)MX2')
  security_warning(0);
else if (version == '12.2(4r)B')
  security_warning(0);
else if (version == '12.2(4r)B1')
  security_warning(0);
else if (version == '12.2(4r)B2')
  security_warning(0);
else if (version == '12.2(4r)B3')
  security_warning(0);
else if (version == '12.2(4r)B4')
  security_warning(0);
else if (version == '12.2(4r)XL')
  security_warning(0);
else if (version == '12.2(4r)XM')
  security_warning(0);
else if (version == '12.2(4r)XM1')
  security_warning(0);
else if (version == '12.2(4r)XM2')
  security_warning(0);
else if (version == '12.2(4r)XM3')
  security_warning(0);
else if (version == '12.2(4r)XM4')
  security_warning(0);
else if (version == '12.2(4r)XT')
  security_warning(0);
else if (version == '12.2(4r)XT1')
  security_warning(0);
else if (version == '12.2(4r)XT2')
  security_warning(0);
else if (version == '12.2(4r)XT3')
  security_warning(0);
else if (version == '12.2(4r)XT4')
  security_warning(0);
else if (version == '12.2(4)T')
  security_warning(0);
else if (version == '12.2(4)T1')
  security_warning(0);
else if (version == '12.2(4)T2')
  security_warning(0);
else if (version == '12.2(4)T3')
  security_warning(0);
else if (version == '12.2(4)T4')
  security_warning(0);
else if (version == '12.2(4)T5')
  security_warning(0);
else if (version == '12.2(4)T6')
  security_warning(0);
else if (version == '12.2(4)T7')
  security_warning(0);
else if (version == '12.2(4)XF')
  security_warning(0);
else if (version == '12.2(4)XF1')
  security_warning(0);
else if (version == '12.2(4)XL')
  security_warning(0);
else if (version == '12.2(4)XL1')
  security_warning(0);
else if (version == '12.2(4)XL2')
  security_warning(0);
else if (version == '12.2(4)XL3')
  security_warning(0);
else if (version == '12.2(4)XL4')
  security_warning(0);
else if (version == '12.2(4)XL5')
  security_warning(0);
else if (version == '12.2(4)XL6')
  security_warning(0);
else if (version == '12.2(4)XM')
  security_warning(0);
else if (version == '12.2(4)XM1')
  security_warning(0);
else if (version == '12.2(4)XM2')
  security_warning(0);
else if (version == '12.2(4)XM3')
  security_warning(0);
else if (version == '12.2(4)XM4')
  security_warning(0);
else if (version == '12.2(4)XR')
  security_warning(0);
else if (version == '12.2(4)XV')
  security_warning(0);
else if (version == '12.2(4)XV1')
  security_warning(0);
else if (version == '12.2(4)XV2')
  security_warning(0);
else if (version == '12.2(4)XV3')
  security_warning(0);
else if (version == '12.2(4)XV4')
  security_warning(0);
else if (version == '12.2(4)XV4a')
  security_warning(0);
else if (version == '12.2(4)XV5')
  security_warning(0);
else if (version == '12.2(4)XW')
  security_warning(0);
else if (version == '12.2(4)XZ')
  security_warning(0);
else if (version == '12.2(4)XZ1')
  security_warning(0);
else if (version == '12.2(4)XZ2')
  security_warning(0);
else if (version == '12.2(4)XZ3')
  security_warning(0);
else if (version == '12.2(4)XZ4')
  security_warning(0);
else if (version == '12.2(4)XZ5')
  security_warning(0);
else if (version == '12.2(4)XZ6')
  security_warning(0);
else if (version == '12.2(4)XZ7')
  security_warning(0);
else if (version == '12.2(4)YA')
  security_warning(0);
else if (version == '12.2(4)YA1')
  security_warning(0);
else if (version == '12.2(4)YA2')
  security_warning(0);
else if (version == '12.2(4)YB')
  security_warning(0);
else if (version == '12.2(4)YF')
  security_warning(0);
else if (version == '12.2(4)YH')
  security_warning(0);
else if (version == '12.2(5)')
  security_warning(0);
else if (version == '12.2(5a)')
  security_warning(0);
else if (version == '12.2(5b)')
  security_warning(0);
else if (version == '12.2(5c)')
  security_warning(0);
else if (version == '12.2(5d)')
  security_warning(0);
else if (version == '12.2(5)DA')
  security_warning(0);
else if (version == '12.2(5)DA1')
  security_warning(0);
else if (version == '12.2(6)')
  security_warning(0);
else if (version == '12.2(6a)')
  security_warning(0);
else if (version == '12.2(6b)')
  security_warning(0);
else if (version == '12.2(6c)')
  security_warning(0);
else if (version == '12.2(6c)M1')
  security_warning(0);
else if (version == '12.2(6c)TEST')
  security_warning(0);
else if (version == '12.2(6d)')
  security_warning(0);
else if (version == '12.2(6e)')
  security_warning(0);
else if (version == '12.2(6f)')
  security_warning(0);
else if (version == '12.2(6f)M1')
  security_warning(0);
else if (version == '12.2(6g)')
  security_warning(0);
else if (version == '12.2(6r)')
  security_warning(0);
else if (version == '12.2(7)')
  security_warning(0);
else if (version == '12.2(7a)')
  security_warning(0);
else if (version == '12.2(7b)')
  security_warning(0);
else if (version == '12.2(7c)')
  security_warning(0);
else if (version == '12.2(7d)')
  security_warning(0);
else if (version == '12.2(7)DA')
  security_warning(0);
else if (version == '12.2(7e)')
  security_warning(0);
else if (version == '12.2(7f)')
  security_warning(0);
else if (version == '12.2(7g)')
  security_warning(0);
else if (version == '12.2(7r)')
  security_warning(0);
else if (version == '12.2(7r)XM')
  security_warning(0);
else if (version == '12.2(7r)XM1')
  security_warning(0);
else if (version == '12.2(7r)XM2')
  security_warning(0);
else if (version == '12.2(7r)XM3')
  security_warning(0);
else if (version == '12.2(7r)XM4')
  security_warning(0);
else if (version == '12.2(7r)XM5')
  security_warning(0);
else if (version == '12.2(8)B')
  security_warning(0);
else if (version == '12.2(8)B1')
  security_warning(0);
else if (version == '12.2(8)B2')
  security_warning(0);
else if (version == '12.2(8)BC1')
  security_warning(0);
else if (version == '12.2(8)BC2')
  security_warning(0);
else if (version == '12.2(8)BC2a')
  security_warning(0);
else if (version == '12.2(8)BY')
  security_warning(0);
else if (version == '12.2(8)BY1')
  security_warning(0);
else if (version == '12.2(8)BY2')
  security_warning(0);
else if (version == '12.2(8)BZ')
  security_warning(0);
else if (version == '12.2(8)JA')
  security_warning(0);
else if (version == '12.2(8)MC1')
  security_warning(0);
else if (version == '12.2(8)MC2')
  security_warning(0);
else if (version == '12.2(8)MC2a')
  security_warning(0);
else if (version == '12.2(8)MC2b')
  security_warning(0);
else if (version == '12.2(8)MC2c')
  security_warning(0);
else if (version == '12.2(8)MC2d')
  security_warning(0);
else if (version == '12.2(8r)')
  security_warning(0);
else if (version == '12.2(8r)B')
  security_warning(0);
else if (version == '12.2(8r)B1')
  security_warning(0);
else if (version == '12.2(8r)B2')
  security_warning(0);
else if (version == '12.2(8r)B3')
  security_warning(0);
else if (version == '12.2(8r)B3a')
  security_warning(0);
else if (version == '12.2(8r)MC1')
  security_warning(0);
else if (version == '12.2(8r)MC2')
  security_warning(0);
else if (version == '12.2(8r)MC3')
  security_warning(0);
else if (version == '12.2(8r)T')
  security_warning(0);
else if (version == '12.2(8r)T1')
  security_warning(0);
else if (version == '12.2(8r)T2')
  security_warning(0);
else if (version == '12.2(8r)T3')
  security_warning(0);
else if (version == '12.2(8)T')
  security_warning(0);
else if (version == '12.2(8)T0a')
  security_warning(0);
else if (version == '12.2(8)T0b')
  security_warning(0);
else if (version == '12.2(8)T0c')
  security_warning(0);
else if (version == '12.2(8)T0d')
  security_warning(0);
else if (version == '12.2(8)T0e')
  security_warning(0);
else if (version == '12.2(8)T1')
  security_warning(0);
else if (version == '12.2(8)T10')
  security_warning(0);
else if (version == '12.2(8)T2')
  security_warning(0);
else if (version == '12.2(8)T3')
  security_warning(0);
else if (version == '12.2(8)T4')
  security_warning(0);
else if (version == '12.2(8)T4a')
  security_warning(0);
else if (version == '12.2(8)T5')
  security_warning(0);
else if (version == '12.2(8)T6')
  security_warning(0);
else if (version == '12.2(8)T7')
  security_warning(0);
else if (version == '12.2(8)T8')
  security_warning(0);
else if (version == '12.2(8)T9')
  security_warning(0);
else if (version == '12.2(8)TPC10a')
  security_warning(0);
else if (version == '12.2(8)YD')
  security_warning(0);
else if (version == '12.2(8)YD1')
  security_warning(0);
else if (version == '12.2(8)YD2')
  security_warning(0);
else if (version == '12.2(8)YD3')
  security_warning(0);
else if (version == '12.2(8)YJ')
  security_warning(0);
else if (version == '12.2(8)YJ1')
  security_warning(0);
else if (version == '12.2(8)YY')
  security_warning(0);
else if (version == '12.2(8)YY1')
  security_warning(0);
else if (version == '12.2(8)YY2')
  security_warning(0);
else if (version == '12.2(8)YY3')
  security_warning(0);
else if (version == '12.2(8)YY4')
  security_warning(0);
else if (version == '12.2(8)ZB')
  security_warning(0);
else if (version == '12.2(8)ZB1')
  security_warning(0);
else if (version == '12.2(8)ZB2')
  security_warning(0);
else if (version == '12.2(8)ZB3')
  security_warning(0);
else if (version == '12.2(8)ZB4')
  security_warning(0);
else if (version == '12.2(8)ZB4a')
  security_warning(0);
else if (version == '12.2(8)ZB5')
  security_warning(0);
else if (version == '12.2(8)ZB6')
  security_warning(0);
else if (version == '12.2(8)ZB7')
  security_warning(0);
else if (version == '12.2(8)ZB8')
  security_warning(0);
else if (version == '12.2(9)S')
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
else if (version == '12.3(10r)')
  security_warning(0);
else if (version == '12.9(9)S0225')
  security_warning(0);
else
  audit(AUDIT_HOST_NOT, 'affected');
