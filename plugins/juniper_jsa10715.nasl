#TRUSTED a8be18511481dba0b19805459bee7586aa416f137e0c3a8ec28d578b02a38152adc2d605aed61293ff311eaad986b105d1d22073edddb40297d23c283b9090e33845bbf60c737ca89754bfdf2617a116c1cdbd9a9d153409374ed54763f1c75aa65c3a55e59968292f5ab9a7481aef777201dd04ec45a4cfdf8a39f3a463f698343e5cddb8c693d570ccc1e8e887cae23d91edd64e0b107b3c0818e582be608e9ac2f0d1c4895e60a28a10999cac5552a8933b54578824649bcb7baed797e6591fa0e7d848a348e036fed6b3bfdfda9e6db366280ce3791ba19cd85bde5719470f43a1f53e10fa56caf86da298d99df6e648dc940dfd62836738ba0da3477a0aa42c72ac4439ea9b6d061acb65719990a42b64a3a43c643d564b18be734e0d48470d794c46ed409dedad7dcdd128ee2cb588be9f0a2de1a4ace16b003606c062ca3087cb8245aa59aaa5aced7cf8ea13b742a7dddc095a8e17d0c77e1d82b531cd510004efa4f663746605457d039383f1508bbe36d48587ebc69991098335c0ee4eddc73b337256b9012340bebcd702af0a35ba4b430742ceb2279e565bc4399956dc1764c11d405006e549584fdb6b3d53a7694d1083e79cb375f1076079013b21b306bc009acfa41efa76b00a20ed3dcadc05a5d1cb3e303a20912e908f890e81f6e8ca8c283e3fc7d79231530a0c1ffb915ff24c7c29b00032b69a3749ae
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88092);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2016-1257");
  script_osvdb_id(132864);
  script_xref(name:"JSA", value:"JSA10715");

  script_name(english:"Juniper Junos RPD Routing Process DoS (JSA10715)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
a flaw in the Label Distribution Protocol (LDP) implementation. An
unauthenticated, remote attacker attacker can exploit this, by sending
a specially crafted LDP packet, to cause the RDP routing process to
crash and restart.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10715");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10715.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['13.3']    = '13.3R7-S3';   # or 13.3R8
fixes['14.1']    = '14.1R3-S9';   # or 14.1R4-S7 / 14.1R6
fixes['14.1X53'] = '14.1X53-D35';
fixes['14.2']    = '14.2R3-S4';   # or 14.2R4-S1 / 14.2R5
fixes['15.1']    = '15.1F2-S2';   # or 15.1F3
fixes['15.1R']   = '15.1R3';
fixes['15.1X49'] = '15.1X49-D40';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "13.3R7-S3")
  fix += " or 13.3R8";
if (fix == "14.1R3-S9")
  fix += " or 14.1R4-S7 or 14.1R6";
if (fix == "14.2R3-S4")
  fix += "or 14.2R4-S1 or 14.2R5";
if (fix == "15.1F2-S2")
  fix += "or 15.1F3";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols ldp";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because ldp is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
