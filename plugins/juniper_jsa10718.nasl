#TRUSTED 9928bf8cab4be335e3bce5adf529212881c728a8444c9cae5b4e7fb1de4de0d958a2762fb8371d3fc9fd3692668f35802dde5b40de0efbc1cf7898290544549662d08573793946e1ae72318a1c0e3415652e358891e4e4022d2570abe9df726bd8f02823d167e7b6204af787f5444623ea2c8487e6c15597835a75747b716c48b82d9f889158fe3814f288cbc453ec47b0bd238e70ea3eaee1335975bde51b8eea8bc15efe5904bc7e8fc1cfdc3d0c902503fbee9666dce500a30828f2a71a7c565bf6708839edaf6820ce01711193ed02d517f0342947250b380f5f0741a6c8a0d447522e458d5ec69e453325e2eebef8a04531e5236d7914a560f4c5871a42b3d3f3e47e290efe050e547b1b44fbf586c5a076847c7ca4144a587ac79b49a26468fa05daff8d2833d35fa5257d2564104d4054d3ef960d05a7583a321eb3de5a0205f700ff21c9b74503900ce5e2ad9519c69f4951303533bb92d4fa0dea004780e23cc4470473f14b32b987ff41d77237577f47a6cf292f70f74557087b356905317c45f197a0b725f24967a34e7da17b5495c20fa9fbb2bac403e793084ab9898f239e448b71be91adcacc77869864728b13fb2a76a655617a262d12e36ad02ccee81d39dfd887a2c7730681f7faa188190845e279f536bb4040bfed9ae29c5c189d007406ead82b434a60b148ad2f04cc0836b97be8540c0020e52596cd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88093);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-5477");
  script_bugtraq_id(76092);
  script_osvdb_id(125438);
  script_xref(name:"JSA", value:"JSA10718");
  script_xref(name:"EDB-ID", value:"37721");
  script_xref(name:"EDB-ID", value:"37723");

  script_name(english:"Juniper Junos TKEY Query Handling DoS (JSA10718)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
a flaw in ISC BIND when handling queries for TKEY records. An
unauthenticated, remote attacker can exploit this, via crafted TKEY
queries, to cause an REQUIRE assertion failure and daemon exit.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10718");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10718.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/28");
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

fixes['12.1X44'] = '12.1X44-D55';
fixes['12.1X46'] = '12.1X46-D40'; # or 12.1X46-D45
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'   ] = '12.3R11'; # or 12.3R12
fixes['12.3X48'] = '12.3X48-D20';
fixes['12.3X50'] = '12.3X50-D50';
fixes['13.2'   ] = '13.2R9';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3'   ] = '13.3R8';
fixes['14.1'   ] = '14.1R6'; # or 14.1R7
fixes['14.1X53'] = '14.1X53-D30';
fixes['14.2'   ] = '14.2R5';
fixes['15.1R'  ] = '15.1R5'; # or 15.1R3
fixes['15.1F'  ] = '15.1F3';
fixes['15.1X49'] = '15.1X49-D30';
fixes['15.1X53'] = '15.1X53-D20';
fixes['15.2R'  ] = '15.2R1';

check_model(model:model, flags:J_SERIES | SRX_SERIES, exit_on_fail:TRUE);

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "15.1R5")
  fix += " or 15.1R3";
if (fix == "14.1R6")
  fix += " or 14.1R7";
if (fix == "12.3R11")
  fix += " or 12.3R12";
if (fix == "12.1X46-D40")
  fix += " or 12.1X46-D45";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services dns dns-proxy";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because proxy-dns settings have not been configured');
  override = FALSE;
}


junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_HOLE);
