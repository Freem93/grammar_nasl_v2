#TRUSTED 2611c02b9fcba35d2c13e0421e5d8a2f3fa29ec1c4fe0230070bbea3e956a45c2832e360570fc91a0828dda5ac29938af4ff5ed0d806db037a94271a060e0cf1f36ae29ee6944016a6873f6217ea86f5d856e74580a73a8105f4e490d4ef18dcb6e9d877dfceb968888164a1a02994257ec008e19bd1bb68c2362d530ff11b4e32eeb65bfc91e493b0cf64f7ea0760041ed2eeccf39206270e1280861ee8061d800fed4da133834e36dbea1860e108d648be3d357946bf3003d89d62062e06756688e05312d28b07065130398a9e3ed39e2633c20c2018af8c37c7fea3e64c94d589cb1e33e377d31deaadbe86f055e2d8c21eea6f671c0745105433cbebc39be94fd5fed15e909fd3cef2bdc02539226948eab917facd0b2075d06b25cafe0fec9da696404f909304cd5b0952ea44bae6e55799b794f35d842b9fe3e62e4d1326960086da77a4351bf8ff687e49565a5672fd8e7e887393f22330c8ea744bb5d4b7afc69546cd9ef14a6ffa2ab811179baa952a47618cb4655e6466763365ef0e0fe65fcc2d1d37865cabae998c72784601ed4002d18ec3d333d7e25a46f63d15c8123b949c584dbcda5f54298d267f4ee4015c10f184de73fc803d4e9122e8b8c27f8d845a2fdf9ae207784526604c27f9a86f0972907b7320c5ef87a95af1de88369c1a62a46fa5c297409fae8557ba9b8ff768729b5f7b1008b7bd1778ce
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97943);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3849");
  script_bugtraq_id(96972);
  script_osvdb_id(154052);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42717");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-ani");

  script_name(english:"Cisco IOS ANI Registrar DoS (cisco-sa-20170320-ani)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Autonomic Networking Infrastructure (ANI) registrar feature
due to incomplete input validation of certain crafted packets. An
unauthenticated, adjacent attacker can exploit this issue, via
specially crafted autonomic network channel discovery packets, to
cause the device to reload.

Note that this issue only affect devices with ANI enabled that are
configured as an autonomic registrar and that have a whitelist
configured.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-ani
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?206d164a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-ani.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

affected_versions = [
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S6',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.3(3)S8',
  '15.3(3)S9',
  '15.2(3)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(5)E',
  '15.2(4)E3',
  '15.2(5a)E',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.4(1)S',
  '15.4(3)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(2)S1',
  '15.4(1)S3',
  '15.4(3)S1',
  '15.4(2)S2',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(1)S4',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.4(3)S6',
  '15.4(3)S6a',
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(2)S4',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T2',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SN',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a'
];

foreach affected_version (affected_versions)
  if (ver == affected_version)
    flag++;

# Check that ANI is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if (
      ( !empty_or_null(buf) ) &&
      ( "no autonomic" >!< buf )
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag) security_report_cisco(severity:SECURITY_WARNING, port:0, version:ver, bug_id:'CSCvc42717', override:override);
else audit(AUDIT_HOST_NOT, "affected");
