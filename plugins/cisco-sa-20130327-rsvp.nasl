#TRUSTED 076c01313dc0a6d1d1c2cd4822995fc127bd7ae33ccd8011098614636bcb695d613ec4b62271ead6758d33dec26932eaf5333164aee173cccbff07b7c68a1cdfbc335f2c412cd2efd87a1f20a88e86fd3ce27baf41e8042faa67f3dff81c214d520d27cc9bb8a01b029d2e6c076a75b974dfa3d3843d3d05d3c8d9c001219bd94bf0cc4c008527c958510d462bed02ff9edfa217232c9ebca334fab23b5445a3f6327815e855187cb2c4594785e2c696ee3560ca0f46f1752ed99f58aa7fd886ceb534861dcd60e273980860b4206603e78fceb57e697a7d1a916bb68c75d4d696661f02e3d1998581ef329d3446689f85f861f521369169bb78fab5afa472d881129f79863a65b4dec7c57c3fba426467ccaafc760148d687232137c87cd45ed9ef4334a61410f831a1d69ea0c889c6247e8222da6a7a4b1c25af5c68e4c5225684656c3e717d9fe36673387c4bafeaeff2f79e8db233d0e9c3dc4daa2a3bec16ae93fb09ae4aabacb2fc0e1385b343790e6a213122a8d59fe09d1eeee751f7368b4adc57f3d599972af238ae2b5b88aeb0533cdb5426e1d124eda547e7af7df5969ca518ca1c434456686eaa6b7856e427a2b9a1691190486f4d0deb7d628a27323540a8a3b297c6b5b9194ed47636646eecfb2dad1ae7c1e68f8b63f3458d669df034fe4be883ba7c5d3334ae9bf4ad44f6d07df1a0931f2d0498f9ad984c
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-rsvp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65890);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-1143");
  script_bugtraq_id(58743);
  script_osvdb_id(91757);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg39957");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-rsvp");

  script_name(english:"Cisco IOS Software Resource Reservation Protocol Denial of Service Vulnerability (cisco-sa-20130327-rsvp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Resource Reservation Protocol (RSVP) feature in Cisco IOS Software
and Cisco IOS XE Software contains a vulnerability when used on a
device that has Multiprotocol Label Switching with Traffic Engineering
(MPLS-TE) enabled. Successful exploitation of the vulnerability could
allow an unauthenticated, remote attacker to cause a reload of the
affected device. Repeated exploitation could result in a sustained
denial of service (DoS) condition. Cisco has released free software
updates that address this vulnerability. There are no workarounds
available to mitigate this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-rsvp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3599bd93"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-rsvp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if ( version == '12.2(33)SRE' ) flag++;
if ( version == '12.2(33)SRE0a' ) flag++;
if ( version == '12.2(33)SRE1' ) flag++;
if ( version == '12.2(33)SRE2' ) flag++;
if ( version == '12.2(33)SRE3' ) flag++;
if ( version == '12.2(33)SRE4' ) flag++;
if ( version == '12.2(33)SRE5' ) flag++;
if ( version == '12.2(33)SRE6' ) flag++;
if ( version == '12.2(33)SRE7' ) flag++;
if ( version == '12.2(33)SRE7a' ) flag++;
if ( version == '12.2(33)ZI' ) flag++;
if ( version == '12.2(58)EX' ) flag++;
if ( version == '12.2(58)EZ' ) flag++;
if ( version == '12.2(58)SE2' ) flag++;
if ( version == '15.0(1)MR' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3a' ) flag++;
if ( version == '15.0(1)S4' ) flag++;
if ( version == '15.0(1)S4a' ) flag++;
if ( version == '15.0(1)S5' ) flag++;
if ( version == '15.0(1)S6' ) flag++;
if ( version == '15.0(2)MR' ) flag++;
if ( version == '15.1(1)MR' ) flag++;
if ( version == '15.1(1)MR1' ) flag++;
if ( version == '15.1(1)MR2' ) flag++;
if ( version == '15.1(1)MR3' ) flag++;
if ( version == '15.1(1)MR4' ) flag++;
if ( version == '15.1(1)MR5' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)SY' ) flag++;
if ( version == '15.1(2)EY' ) flag++;
if ( version == '15.1(2)EY1' ) flag++;
if ( version == '15.1(2)EY1a' ) flag++;
if ( version == '15.1(2)EY2' ) flag++;
if ( version == '15.1(2)EY2a' ) flag++;
if ( version == '15.1(2)EY3' ) flag++;
if ( version == '15.1(2)EY4' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)S2' ) flag++;
if ( version == '15.1(2)SNG' ) flag++;
if ( version == '15.1(2)SNH' ) flag++;
if ( version == '15.1(2)SNH1' ) flag++;
if ( version == '15.1(2)SNI' ) flag++;
if ( version == '15.1(3)MR' ) flag++;
if ( version == '15.1(3)MRA' ) flag++;
if ( version == '15.1(3)S' ) flag++;
if ( version == '15.1(3)S0a' ) flag++;
if ( version == '15.1(3)S1' ) flag++;
if ( version == '15.1(3)S2' ) flag++;
if ( version == '15.1(3)S3' ) flag++;
if ( version == '15.1(3)S4' ) flag++;
if ( version == '15.2(1)S' ) flag++;
if ( version == '15.2(1)S1' ) flag++;
if ( version == '15.2(1)S2' ) flag++;
if ( version == '15.2(1)SA' ) flag++;
if ( version == '15.2(1)SB' ) flag++;
if ( version == '15.2(1)SB1' ) flag++;
if ( version == '15.2(1)SB2' ) flag++;
if ( version == '15.2(1)SB3' ) flag++;
if ( version == '15.2(1)SB4' ) flag++;
if ( version == '15.2(1)SC' ) flag++;
if ( version == '15.2(1)SC1' ) flag++;
if ( version == '15.2(2)S' ) flag++;
if ( version == '15.2(2)S0a' ) flag++;
if ( version == '15.2(2)S0b' ) flag++;
if ( version == '15.2(2)S0c' ) flag++;
if ( version == '15.2(2)S0d' ) flag++;
if ( version == '15.2(2)S1' ) flag++;
if ( version == '15.2(2)S2' ) flag++;
if ( version == '15.2(2)SNG' ) flag++;
if ( version == '15.2(2)SNH' ) flag++;
if ( version == '15.2(2)SNH1' ) flag++;
if ( version == '15.2(4)S' ) flag++;
if ( version == '15.2(4)S0c' ) flag++;
if ( version == '15.2(4)S0xb' ) flag++;
if ( version == '15.2(4)S1' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"mpls traffic-eng tunnels", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
