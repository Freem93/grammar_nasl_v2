#TRUSTED 12cd5c82b9ef03fa608d6ed1ff7e5b3e6d33965dd7527d7fb67deabec1f200acbed93b60cfc6837c23f1eea98b8660386fb911feb66541eec8ec0be690b0c7d9df39c99bda8dc607fd78b82aa0cd0b5ccd437715fa5149354db280f9727f241301f59e0f6c9879a55e04f1368761a8cf37b3216e5770744966ad0125b8af5ee197a65ce19ec2224bf7d055d1f489bf75f508b7d8b0fdc57e983afe35dfb24749d26ae1e73497388308c3224f0161a95752057a599195e4463d7936ef8740ac19404a2753eee68435fd388216084e7617c1f6fb380fa4bd5f07e7d8f2ecc24a6d766029e2f238aa11e59e64408fec3f25fc5d16b6c60d3b8802f97c807a148a416925a453dfede46343d8c4cdb9531540c9ed33dfa55d8305e0e3184f3ed5757ac12772dc2349bd68f73cbd3c078af0a1aedad801558e337a5e5d2d85bbd735bf09e4d2bdc97a3ac809ff7c6b1fbbcd0f2998861821f3b616355dee1b33b602ffacbd825bf66c124efa8810e1263d1d35d2be560af8c1b98bedefc7fbbf62309aea392ed21e18f9f61e8563e43eee99ffdf65eff1e7cc155f526f8df9d859a3fa426cb36f4ba7b28316e27f73241cc077233a42ddd84d4cf290603ffcf0b7214dbea960d315b9c9def36a317c77b5bdafb223c6f6e1e3a548fd85448893b077f95a7895d1cce0af4343cd88af19106c8996fc7c828f40ee594cbf081f00bbf7a1
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-ipsla.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65887);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-1148");
  script_bugtraq_id(58739);
  script_osvdb_id(91755);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc72594");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-ipsla");

  script_name(english:"Cisco IOS Software IP Service Level Agreement Vulnerability (cisco-sa-20130327-ipsla)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software implementation of the IP Service Level
Agreement (IP SLA) feature contains a vulnerability in the validation
of IP SLA packets that could allow an unauthenticated, remote attacker
to cause a denial of service (DoS) condition. Cisco has released free
software updates that address this vulnerability. Mitigations for this
vulnerability are available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-ipsla
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68bb7681"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-ipsla."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/12");
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
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)S' ) flag++;
if ( version == '15.2(4)S0c' ) flag++;
if ( version == '15.2(4)S0xb' ) flag++;
if ( version == '15.2(4)S1' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip sla responder", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sla_responder", "show ip sla responder");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"General[^\r\n]*Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
