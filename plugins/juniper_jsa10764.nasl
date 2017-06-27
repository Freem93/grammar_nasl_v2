#TRUSTED 6a739fe5d6e1f6ca75b8c8910530697591392e82d7962efee249ed4f8005ea9626c83943b2a3b80d1e280edd7df11b274d6d1e8ec0f333c38c4d8ee77f38eb693a8f5126c40c240180bd0cbbb3b580a8aab40ee715b653f68ef162056c77c23bd0655a20da8f64d89aa08ae76e257a081b09a6589a4559f3011f20ed217d0794dae5c3dfbab2ddd24553645a98d373f31931fc48f89e377be889fb47686ff9c45d59aa321324ab04fc6aa53b5abab94b53e351ea1c044dbda95dffbbd457343c2e1abdbfb40a9a72e9a23c9c3f8e4832203f182e68af6c945a40b861a027cb54e2cba7de65f4a9ff7247410bc399216763476634d9f0839571f3577fcacb7aaee33ec7038c8deefe47307cca9f3c23dd8fd3750f8d66704af931ae9e6c8b10a4167ddcc016812db7c16a7ff259bd08abdeca3655ecbe6a57f935a6b350b597b8166855b8c6e0088d4e33a4d9caff891d8b5e480134483396081cbbb40334afab23f51f35eed27fe0a7113cdac67ff11a52c51a776e2a9f0f49308f933c40ade9466a2789da09a3c335b03c8baf5e101afa9970ba24594399833805bceb169b9453d104a37ef2f5837644df027be10f09078397219af84bbdd87fa2203d41dd1c3a82717fbb30f4a942282aaa63c9d66be372e6ba53e95473c21259edc49cbe9a0d410cbdfb4be275d50c65885a5f8fd8f1ca7174c5115c76f4a201273910023d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94333);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/27");

  script_cve_id("CVE-2016-4923");
  script_bugtraq_id(93529);
  script_osvdb_id(145590);
  script_xref(name:"JSA", value:"JSA10764");

  script_name(english:"Juniper Junos J-Web Reflected XSS (JSA10764)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a cross-site scripting
vulnerability in the J-web component due to improper validation of
user-supplied input. An unauthenticated, remote attacker can exploit
this, via a specially crafted request, to execute arbitrary script
code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10764");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10764.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X44'] = '12.1X44-D60';
fixes['12.1X46'] = '12.1X46-D40';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'] = '12.3R11';
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2X51'] = '13.2X51-D39'; # or 13.2X51-D40
fixes['13.3'] = '13.3R9';
fixes['14.1'] = '14.1R6';
fixes['14.2'] = '14.2R6';
fixes['15.1R'] = '15.1R3';
fixes['15.1X49'] = '15.1X49-D20';
fixes['16.1R'] = '16.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "13.2X51-D39")
  fix += " or 13.2X51-D40";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the web-management service is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING, xss:TRUE);
