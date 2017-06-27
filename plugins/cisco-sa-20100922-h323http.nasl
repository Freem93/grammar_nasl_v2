#TRUSTED 7006ceeb49aac5032a22c405be2a5dd693ae6f22b3c059819912ca80d3a323959e79298f820b3e454dc436870d90651adc893081e26ab4e3ab606b806f6341891a632232a8c268a9206654af97c07269be77483b46387152d49f645e1e494493b5fd88328176281af91044950301a3b0f46481b0eb47365e1789b0f385bec330ab43daff739f13903ea60c5e95a42a13a83bcc762bee7efa9032eed70bdab80ffb014cfefeea8fd59d2f8991f6e76814c1c12ebdb64964a8eaeb12d7cafa1f2081c65efe8415ff17a9e4aff3e34005c9043ae0d65cd8298cf3cfc3c792433e7926a13391f88bbc05e2f5f5f87ae29b1d6cdda5b3000d118b9b2b1f795d7e84bf74af5c22748207e16eb636b79686326e7d2fbec86c32accccd98d60be33b465c6531564ae8f8aacc7552c4ed316667dd6a0e80746545ac390c9e801bbb99343054733d2e2251c9ca61f5db6d9fe239baf8d20743dde4489b819b792fba7f86a61984e54bfba2652f564f1568209d3527952400cd0c6fe6f1841fee93f30d7f7ccbb3a0aa2d59de2ee837a51612af3c6494cd0b2b9c8a518dbbe2149aeac0f61a1d4af542a733378db19f619cb7f16b3dc4c056000b02abc052f26f5f01fac62e05230131d713a984edb75de66c4b1e75f6c841786e5028a588e13ee30659af10a61d489b7827ad331320aa4acfae8fc860b52199ed475ceadabc4643839f3474
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100922-h323.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(49647);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2010-2828", "CVE-2010-2829");
  script_osvdb_id(68196, 68197);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtc73759");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100922-h323");

  script_name(english:"Cisco IOS Software H.323 Denial of Service Vulnerabilities (cisco-sa-20100922-h323)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The H.323 implementation in Cisco IOS Software contains two
vulnerabilities that may be exploited remotely to cause a denial of
service (DoS) condition on a device that is running a vulnerable
version of Cisco IOS Software. Cisco has released free software
updates that address these vulnerabilities. There are no workarounds
to mitigate these vulnerabilities other than disabling H.323 on the
vulnerable device."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100922-h323
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95f878ad"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100922-h323."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/22");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if ( version == '12.1(3)XI' ) flag++;
if ( version == '12.1(3)XQ1' ) flag++;
if ( version == '12.1(3a)XI8' ) flag++;
if ( version == '12.1(3a)XI9' ) flag++;
if ( version == '12.1(3a)XL3' ) flag++;
if ( version == '12.1(5)T10' ) flag++;
if ( version == '12.1(5)T2' ) flag++;
if ( version == '12.1(5)T8a' ) flag++;
if ( version == '12.1(5)T9' ) flag++;
if ( version == '12.1(5)XM4' ) flag++;
if ( version == '12.1(5)XR1' ) flag++;
if ( version == '12.1(5)XS4' ) flag++;
if ( version == '12.1(5)XS5' ) flag++;
if ( version == '12.1(5)XU' ) flag++;
if ( version == '12.1(5)YA2' ) flag++;
if ( version == '12.1(5)YD6' ) flag++;
if ( version == '12.1(5)YF2' ) flag++;
if ( version == '12.2(1)M0' ) flag++;
if ( version == '12.2(11)T5' ) flag++;
if ( version == '12.2(11)T8' ) flag++;
if ( version == '12.2(12e)' ) flag++;
if ( version == '12.2(13)T10' ) flag++;
if ( version == '12.2(13)T2' ) flag++;
if ( version == '12.2(13)T5' ) flag++;
if ( version == '12.2(13)T8' ) flag++;
if ( version == '12.2(13)ZH5' ) flag++;
if ( version == '12.2(13)ZH9' ) flag++;
if ( version == '12.2(14)S11' ) flag++;
if ( version == '12.2(14)S7' ) flag++;
if ( version == '12.2(14)SU1' ) flag++;
if ( version == '12.2(15)CZ1' ) flag++;
if ( version == '12.2(15)MC1b' ) flag++;
if ( version == '12.2(15)MC1c' ) flag++;
if ( version == '12.2(15)ZJ2' ) flag++;
if ( version == '12.2(16)B1' ) flag++;
if ( version == '12.2(17d)SXB6' ) flag++;
if ( version == '12.2(18)SV3' ) flag++;
if ( version == '12.2(18)SXD1' ) flag++;
if ( version == '12.2(19b)' ) flag++;
if ( version == '12.2(1a)XC1' ) flag++;
if ( version == '12.2(2)T1' ) flag++;
if ( version == '12.2(2)T4' ) flag++;
if ( version == '12.2(2)XA2' ) flag++;
if ( version == '12.2(2)XB11' ) flag++;
if ( version == '12.2(2)XG1' ) flag++;
if ( version == '12.2(2)XQ' ) flag++;
if ( version == '12.2(2)XT2' ) flag++;
if ( version == '12.2(2)YC1' ) flag++;
if ( version == '12.2(2)YC4' ) flag++;
if ( version == '12.2(20)S10' ) flag++;
if ( version == '12.2(22)S2' ) flag++;
if ( version == '12.2(22)SV1' ) flag++;
if ( version == '12.2(24b)' ) flag++;
if ( version == '12.2(25)SW2' ) flag++;
if ( version == '12.2(25)SW9' ) flag++;
if ( version == '12.2(27)SBB4e' ) flag++;
if ( version == '12.2(27)SBC2' ) flag++;
if ( version == '12.2(27)SBC3' ) flag++;
if ( version == '12.2(28)SB10' ) flag++;
if ( version == '12.2(28)SB11' ) flag++;
if ( version == '12.2(28)SB13' ) flag++;
if ( version == '12.2(28)SB5c' ) flag++;
if ( version == '12.2(29)SV3' ) flag++;
if ( version == '12.2(31)SB3x' ) flag++;
if ( version == '12.2(31)SB5' ) flag++;
if ( version == '12.2(33)SB3' ) flag++;
if ( version == '12.2(33)SCB' ) flag++;
if ( version == '12.2(33)SCB6' ) flag++;
if ( version == '12.2(33)SRC2' ) flag++;
if ( version == '12.2(33)SRD6' ) flag++;
if ( version == '12.2(33)SRD7' ) flag++;
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(4)BW1a' ) flag++;
if ( version == '12.2(4)XM3' ) flag++;
if ( version == '12.2(4)XV1' ) flag++;
if ( version == '12.2(4)XV2' ) flag++;
if ( version == '12.2(4)XV4' ) flag++;
if ( version == '12.2(4)YA3' ) flag++;
if ( version == '12.2(4)YA6' ) flag++;
if ( version == '12.2(8)T8' ) flag++;
if ( version == '12.2(8)YD3' ) flag++;
if ( version == '12.2(8)YL' ) flag++;
if ( version == '12.2(8)YY4' ) flag++;
if ( version == '12.2(8)ZB2' ) flag++;
if ( version == '12.2(8)ZB3' ) flag++;
if ( version == '12.3(11)YF2' ) flag++;
if ( version == '12.3(14)YM12' ) flag++;
if ( version == '12.3(14)YM3' ) flag++;
if ( version == '12.3(14)YM4' ) flag++;
if ( version == '12.3(14)YQ4' ) flag++;
if ( version == '12.3(14)YQ5' ) flag++;
if ( version == '12.3(14)YX10' ) flag++;
if ( version == '12.3(14)YX8' ) flag++;
if ( version == '12.3(2)T9' ) flag++;
if ( version == '12.3(2)XA4' ) flag++;
if ( version == '12.3(3)B1' ) flag++;
if ( version == '12.3(4)T2a' ) flag++;
if ( version == '12.3(4)T9' ) flag++;
if ( version == '12.3(4)XD1' ) flag++;
if ( version == '12.3(4)XD4' ) flag++;
if ( version == '12.3(4)XK3' ) flag++;
if ( version == '12.3(7)XI7' ) flag++;
if ( version == '12.3(8)T6' ) flag++;
if ( version == '12.3(8)T9' ) flag++;
if ( version == '12.3(8)XY3' ) flag++;
if ( version == '12.4(11)MR' ) flag++;
if ( version == '12.4(11)T' ) flag++;
if ( version == '12.4(11)T1' ) flag++;
if ( version == '12.4(11)T2' ) flag++;
if ( version == '12.4(11)T3' ) flag++;
if ( version == '12.4(11)T4' ) flag++;
if ( version == '12.4(11)XJ' ) flag++;
if ( version == '12.4(11)XJ1' ) flag++;
if ( version == '12.4(11)XJ2' ) flag++;
if ( version == '12.4(11)XJ3' ) flag++;
if ( version == '12.4(11)XJ4' ) flag++;
if ( version == '12.4(11)XJ5' ) flag++;
if ( version == '12.4(11)XJ6' ) flag++;
if ( version == '12.4(11)XV' ) flag++;
if ( version == '12.4(11)XV1' ) flag++;
if ( version == '12.4(11)XW' ) flag++;
if ( version == '12.4(11)XW1' ) flag++;
if ( version == '12.4(11)XW10' ) flag++;
if ( version == '12.4(11)XW2' ) flag++;
if ( version == '12.4(11)XW3' ) flag++;
if ( version == '12.4(11)XW4' ) flag++;
if ( version == '12.4(11)XW5' ) flag++;
if ( version == '12.4(11)XW6' ) flag++;
if ( version == '12.4(11)XW7' ) flag++;
if ( version == '12.4(11)XW8' ) flag++;
if ( version == '12.4(11)XW9' ) flag++;
if ( version == '12.4(12)MR' ) flag++;
if ( version == '12.4(12)MR1' ) flag++;
if ( version == '12.4(12)MR2' ) flag++;
if ( version == '12.4(15)T' ) flag++;
if ( version == '12.4(15)T1' ) flag++;
if ( version == '12.4(15)T10' ) flag++;
if ( version == '12.4(15)T11' ) flag++;
if ( version == '12.4(15)T12' ) flag++;
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(15)T2' ) flag++;
if ( version == '12.4(15)T3' ) flag++;
if ( version == '12.4(15)T4' ) flag++;
if ( version == '12.4(15)T5' ) flag++;
if ( version == '12.4(15)T6' ) flag++;
if ( version == '12.4(15)T6a' ) flag++;
if ( version == '12.4(15)T7' ) flag++;
if ( version == '12.4(15)T8' ) flag++;
if ( version == '12.4(15)T9' ) flag++;
if ( version == '12.4(15)XL' ) flag++;
if ( version == '12.4(15)XL1' ) flag++;
if ( version == '12.4(15)XL2' ) flag++;
if ( version == '12.4(15)XL3' ) flag++;
if ( version == '12.4(15)XL4' ) flag++;
if ( version == '12.4(15)XL5' ) flag++;
if ( version == '12.4(15)XM1' ) flag++;
if ( version == '12.4(15)XM2' ) flag++;
if ( version == '12.4(15)XY' ) flag++;
if ( version == '12.4(15)XY1' ) flag++;
if ( version == '12.4(15)XY2' ) flag++;
if ( version == '12.4(15)XY3' ) flag++;
if ( version == '12.4(15)XY4' ) flag++;
if ( version == '12.4(15)XY5' ) flag++;
if ( version == '12.4(15)XZ' ) flag++;
if ( version == '12.4(15)XZ1' ) flag++;
if ( version == '12.4(15)XZ2' ) flag++;
if ( version == '12.4(16)MR' ) flag++;
if ( version == '12.4(16)MR1' ) flag++;
if ( version == '12.4(16)MR2' ) flag++;
if ( version == '12.4(18b)' ) flag++;
if ( version == '12.4(18e)' ) flag++;
if ( version == '12.4(19)MR' ) flag++;
if ( version == '12.4(19)MR1' ) flag++;
if ( version == '12.4(19)MR2' ) flag++;
if ( version == '12.4(2)XA' ) flag++;
if ( version == '12.4(2)XA1' ) flag++;
if ( version == '12.4(2)XA2' ) flag++;
if ( version == '12.4(2)XB1' ) flag++;
if ( version == '12.4(2)XB6' ) flag++;
if ( version == '12.4(20)MR' ) flag++;
if ( version == '12.4(20)MR2' ) flag++;
if ( version == '12.4(20)MRA' ) flag++;
if ( version == '12.4(20)T' ) flag++;
if ( version == '12.4(20)T1' ) flag++;
if ( version == '12.4(20)T2' ) flag++;
if ( version == '12.4(20)T3' ) flag++;
if ( version == '12.4(20)T4' ) flag++;
if ( version == '12.4(20)T5' ) flag++;
if ( version == '12.4(20)T5a' ) flag++;
if ( version == '12.4(20)YA' ) flag++;
if ( version == '12.4(20)YA1' ) flag++;
if ( version == '12.4(20)YA2' ) flag++;
if ( version == '12.4(20)YA3' ) flag++;
if ( version == '12.4(22)GC1' ) flag++;
if ( version == '12.4(22)T' ) flag++;
if ( version == '12.4(22)T1' ) flag++;
if ( version == '12.4(22)T2' ) flag++;
if ( version == '12.4(22)T3' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(22)YB' ) flag++;
if ( version == '12.4(22)YB1' ) flag++;
if ( version == '12.4(22)YB4' ) flag++;
if ( version == '12.4(22)YB5' ) flag++;
if ( version == '12.4(22)YB6' ) flag++;
if ( version == '12.4(24)GC1' ) flag++;
if ( version == '12.4(24)T' ) flag++;
if ( version == '12.4(24)T1' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '12.4(4)T8' ) flag++;
if ( version == '12.4(4)XC' ) flag++;
if ( version == '12.4(4)XC1' ) flag++;
if ( version == '12.4(4)XC2' ) flag++;
if ( version == '12.4(4)XC3' ) flag++;
if ( version == '12.4(4)XC4' ) flag++;
if ( version == '12.4(4)XC5' ) flag++;
if ( version == '12.4(4)XC6' ) flag++;
if ( version == '12.4(4)XC7' ) flag++;
if ( version == '12.4(4)XD4' ) flag++;
if ( version == '12.4(6)MR' ) flag++;
if ( version == '12.4(6)MR1' ) flag++;
if ( version == '12.4(6)T' ) flag++;
if ( version == '12.4(6)T1' ) flag++;
if ( version == '12.4(6)T10' ) flag++;
if ( version == '12.4(6)T11' ) flag++;
if ( version == '12.4(6)T12' ) flag++;
if ( version == '12.4(6)T2' ) flag++;
if ( version == '12.4(6)T3' ) flag++;
if ( version == '12.4(6)T4' ) flag++;
if ( version == '12.4(6)T5' ) flag++;
if ( version == '12.4(6)T5a' ) flag++;
if ( version == '12.4(6)T5b' ) flag++;
if ( version == '12.4(6)T6' ) flag++;
if ( version == '12.4(6)T7' ) flag++;
if ( version == '12.4(6)T8' ) flag++;
if ( version == '12.4(6)T9' ) flag++;
if ( version == '12.4(6)XE' ) flag++;
if ( version == '12.4(6)XE1' ) flag++;
if ( version == '12.4(6)XE2' ) flag++;
if ( version == '12.4(6)XE3' ) flag++;
if ( version == '12.4(6)XP' ) flag++;
if ( version == '12.4(6)XT' ) flag++;
if ( version == '12.4(6)XT1' ) flag++;
if ( version == '12.4(6)XT2' ) flag++;
if ( version == '12.4(9)MR' ) flag++;
if ( version == '12.4(9)T' ) flag++;
if ( version == '12.4(9)T0a' ) flag++;
if ( version == '12.4(9)T1' ) flag++;
if ( version == '12.4(9)T2' ) flag++;
if ( version == '12.4(9)T3' ) flag++;
if ( version == '12.4(9)T4' ) flag++;
if ( version == '12.4(9)T5' ) flag++;
if ( version == '12.4(9)T6' ) flag++;
if ( version == '12.4(9)T7' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"H323", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
