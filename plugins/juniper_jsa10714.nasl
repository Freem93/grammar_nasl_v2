#TRUSTED 1d1a14f488eabde955996aada5c5f7674ebc387ad37c09bfb7a847a55ff160e9ef4818955d6552cf92c2e2bce1fa9b9125de7785d9a63edfe4b22a38a648700edb6b8dff516fd65748da37f5175ac3fa88198f841eb21126b240cfe102a24bb373a2486972916fb8de9c84ea853dae6ff165f77cb6951ad7e45a847cc4adc09ad1210937aa3bb58d7273be2d2a514c6280076fb8d3fb942f57a4c308ee96aebb4c32b3926dddd15afd9d009c0b030d67cb23154aa5a89696ded6a75acb051016ae2e95d77aca46b344073b192747932a05e25d100f5eb72c2accd03417e41bcba2ff5c56d4e811d690653a9b8181c4d2910d4b7c6fd6df84a834144d6116c4b4d663beac46bfef5726762afcf03438c6d4df696a00df85ad3d688a9e52a61f6854298ff0c394d4bbdb19cf4b9009ce62f5d838e945e392d6ae55286bcd6c1ce05a1f0f83e28adb688559f6c7b59682ade5bc0655518ca6df5c506cdd9357c784cd2c639b5b33839d0300d90830ce70deb748f4a588e6d2de50bdafc3eb09102a6e72b07e6f53588239580caf8b401551dad5d996a1a2ac768a779a1114518ca1a54eda0605fc5656c9f31745cf6122d1ec285789484f0d5a1d7b608e1ef09b91e07d7312f036669488bc6b9a575d1b90155669779cd5160cd2a60213f5392cc5522a2a924ce0c550be419a6de5e3717c1d5a69e8b7c3a1166273d80c4bdd6d8a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88091);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2016-1256");
  script_osvdb_id(132868);
  script_xref(name:"JSA", value:"JSA10714");

  script_name(english:"Juniper Junos IGMPv3 Protocol Multicast DoS (JSA10714)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
a flaw in the IGMPv3 implementation. An unauthenticated, remote
attacker can exploit this, via a specially crafted IGMPv3 packet, to
affect service availability on a portion of a multicast network. Note
that IGMPv2 is not affected by this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10714");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10714.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
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

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X44'] = '12.1X44-D55';
fixes['12.1X46'] = '12.1X46-D40';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3X48'] = '12.3X48-D15';
fixes['12.3'   ] = '12.3R10';
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2'   ] = '13.2R8';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3'   ] = '13.3R7';
fixes['14.1'   ] = '14.1R5';
fixes['14.1X53'] = '14.1X53-D30';
fixes['14.1X55'] = '14.1X55-D25';
fixes['14.2'   ] = '14.2R4';
fixes['15.1'   ] = '15.1R2';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols imgp";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because imgp is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
