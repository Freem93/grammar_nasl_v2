#TRUSTED 92a95128a7bcb967982dd734a15c5ae151269dcc8411979e459469e60f79ee521a6f49643bad56be84a9c5c1d9457629cd575d16406fc60fb1f4e17d347dca0fed4356c235476f436357871e2b37bb983110c9b35fbd0eae8e8ff9b0177e9265ef5c19b66c6d9844a996fd3f9b1c2e5a32779c93453bb96889d3931806893c659f2909c97c8c96984ca203a32ef36568b1a45d1fb66377995776d324b1f0c129392c93636f9434b29789eb1f8d10af47f479e3f0c27aeb14a40b455a86e4252fc3764b9dc81d3e73c7c0adadff4a54ae12e271799c659b9a02ed104f54d088cef9c961af9e877dc2a07c000061547dfa19dbf1324cc5bcad50e25bd04c143c93efe9d5aa1df8e253e88c157dfcb8d4d24460933aae5b3f7ccb3b8c0714d678d2b6e9cd1374ce3edbc0cdb3e24e54c955a5c6202843179897fb690f0df9243cdd7879e60b159580df88b093e45036d712f72caebeca8ad2153411e84f1c5173ea4af3edf344204b563ac2093bb2c0b21c1a4899923342402e04432ba5ac604dcd1c74cd502fcc8c5003aa368122245c066241c46b6c27768cd8e811074e2e8d9395b60356bc76af4a2fd4c281a01bd9a3eff2fc3296b729175ebbbee59ace625a79233c422bd682dce2a15a13cabf7021b9f3508d443b098d073bc01e316ca3b1a63b3c34671df62ed69a39c51a86da858db02cccd7a9503185f14b588b7bcae3
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-cce.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70314);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-5476");
  script_bugtraq_id(62642);
  script_osvdb_id(97741);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx56174");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-cce");

  script_name(english:"Cisco IOS Software Zone-Based Firewall and Content Filtering Vulnerability (cisco-sa-20130925-cce)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the Zone-Based Firewall (ZBFW) component of Cisco
IOS Software could allow an unauthenticated, remote attacker to cause
an affected device to hang or reload. The vulnerability is due to
improper processing of specific HTTP packets when the device is
configured for either Cisco IOS Content Filtering or HTTP application
layer gateway (ALG) inspection. An attacker could exploit this
vulnerability by sending specific HTTP packets through an affected
device. An exploit could allow the attacker to cause an affected
device to hang or reload. Cisco has released free software updates
that address this vulnerability. Workarounds that mitigate this
vulnerability are not available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-cce
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b969cfcb"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-cce."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

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
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)GC1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2)T3' ) flag++;
if ( version == '15.2(2)T4' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GC1' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)T3' ) flag++;
if ( version == '15.2(3)XA' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"service-policy (urlfilter|http) .*", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair_urlfilter", "show policy-map type inspect zone-pair urlfilter");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"URL Filtering is in", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
