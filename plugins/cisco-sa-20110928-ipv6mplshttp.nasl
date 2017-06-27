#TRUSTED b0ffacf87a7334061abd296186565f1c2b8b9335ca577023e8decd8b1515f9f7d8a7528baec57cd76cda87f8ab4443bd4e1fa78b32774381b12813be243bec70ab3cb852e690e4558413c8fd60a2b990d4e0487bbb4c2a836a071e5bf58e57fb35ff8ed9a43a49c3e8ef3a4beeb7f760ac0d5381b678152ac8df6f3ef6905abbc881c62e0412701a893fbc3e442333314663bb8a839130f63305ef27ab2f2ae2cfe0eb9e9a497745aebcf752059bbf63601d984a536d13a5d5e5ad2dee4153b58e93cbb2a915d73acc75111191dcc4d616753aff536d27467b3825747c1b65ec0194ab5b5acd6f5b7d5036a5bbced1a0481f651a18bc55056856b0ab9c2a474b2306264a3495ea6c88b0f5ac07f00ae8c427fbda6272d4f9ff66de97d96ec1b8ddd81127a9535c326971ab160aab17d0888cccfbc593f5b9883312ef57451d73e63374d8b1de599fba860334154df286de8dda95f6b5bb47c272fd08eb23e5575c43bfb8f6d6f4794991193fb50e50a3e65a03b48e04a6165a204c523fbb69773789cce8851388aea23d096e9da9906455fdeb5f03220286689aa4d98d0fac05ef83f42526960532f21c43a385b4edfcd7ecb6c67104df344cb501fde5d09e42f2b2110fddfdf8365aa200d1a6bc9c7306a26b08856e5bd420341d2e448c47ea9f41d2b686d9914c510014d0e23d9642d3dca51b6df663d3e4ef9889b6d0d84e
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-ipv6mpls.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56317);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2011-3274", "CVE-2011-3282");
  script_bugtraq_id(49827);
  script_osvdb_id(76070, 76071);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj30155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto07919");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-ipv6mpls");

  script_name(english:"Cisco IOS Software IP Version 6 over Multiprotocol Label Switching Vulnerabilities (cisco-sa-20110928-ipv6mpls)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software is affected by two vulnerabilities that cause a
Cisco IOS device to reload when processing IP version 6 (IPv6) packets
over a Multiprotocol Label Switching (MPLS) domain. These
vulnerabilities are :

   - Crafted IPv6 Packet May Cause MPLS-Configured Device to
    Reload

   - ICMPv6 Packet May Cause MPLS-Configured Device to
    Reload

Cisco has released free software updates that address these
vulnerabilities.

Workarounds that mitigate these vulnerabilities are available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-ipv6mpls
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0618c52a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-ipv6mpls."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if ( version == '12.2(33)XNE' ) flag++;
if ( version == '12.2(33)XNE1' ) flag++;
if ( version == '12.2(33)XNE1xb' ) flag++;
if ( version == '12.2(33)XNE2' ) flag++;
if ( version == '12.2(33)XNE3' ) flag++;
if ( version == '12.2(33)XNF' ) flag++;
if ( version == '12.2(33)XNF1' ) flag++;
if ( version == '12.2(33)XNF2' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.0(1)M3' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)MR' ) flag++;
if ( version == '15.0(1)S' ) flag++;
if ( version == '15.0(1)S1' ) flag++;
if ( version == '15.0(1)S2' ) flag++;
if ( version == '15.0(1)S3a' ) flag++;
if ( version == '15.0(1)XA' ) flag++;
if ( version == '15.0(1)XA1' ) flag++;
if ( version == '15.0(1)XA2' ) flag++;
if ( version == '15.0(1)XA3' ) flag++;
if ( version == '15.0(1)XA4' ) flag++;
if ( version == '15.0(1)XA5' ) flag++;
if ( version == '15.0(2)MR' ) flag++;
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)S' ) flag++;
if ( version == '15.1(2)S1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_mpls_interface", "show mpls interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Yes", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
