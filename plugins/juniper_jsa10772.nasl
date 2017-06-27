#TRUSTED 882e52e1a7d2fd575ed987a6b3d73f00d91543cde16d3d4bcbb8288b2579e5d713b5bab1be8173f0baa21b5f9bcecf37cb0f9c7bd4e6677977c701a557391d52402153c36d5f6cffb67f3cea95756a168328719c31558270432c8f6da4651339c2fb98febc5771813d0d39d15693214334f80a83f6f6bca580bb360b6ad85b2cfd49d085a058d65791d974011e8c03da743b79b6db88ae046de11a62598c5c4db3e6d5bb10c00c2c4c93ed6de90f74251306b9edc5fb0d1ca53fa1b5c8d0ba452af51303980f3232d9ce76ae9547b29ffdc0e6b85b54a44d9a91efa627ef1367b4b2bfdd6b8c72c281f4a4c46a99040e8d8b80eba15e4e8a66e47a316ab312636cdf1230c7f9071ab28d44bf53c892997a12d1ce13be89db0168206f9fcc5fed84be230c07070b29feee11c1f601767dcb7a050b4ac60d295d3d1bc3c7b7c51311d80497a9fa48f8ce2424166bd2929a063354379dabf2dd7b3a941910e2470077b652cf3c24aa4dd9fc6155a1af03b19e784fefd02532cb1079172b01fd1168644ba1f8d3ec9d5b40f640cb886a8473fc1dd4f2fcba0b25b4c70ef62c1de03f5dbe9d0b83af620d180bbbebc5c852b1b1c6c29555c25ca1576889d89c0cf62a727d5cbb6acd17dfc6d8112bb8ccf6ffeceba994df6c3222a557b0e3e8cab5b90778cfe26f5f64085f6bf34e0dde9d2c961d0c8035591238679367562323dc4a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96661);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/21");

  script_cve_id("CVE-2017-2303");
  script_bugtraq_id(95408);
  script_osvdb_id(149995);
  script_xref(name:"JSA", value:"JSA10772");

  script_name(english:"Juniper Junos rpd RIP DoS (JSA10772)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the routing process daemon (rpd) due to improper
handling of RIP advertisements. An unauthenticated, remote attacker
can exploit this issue, by sending a specially crafted RIP
advertisement, to cause the rpd daemon to crash and restart.

Note that this vulnerability only affects devices that are configured
with RIP enabled.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10772");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10772.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D50';
fixes['12.1X47'] = '12.1X47-D40';
fixes['12.3']    = '12.3R13';
fixes['12.3X48'] = '12.3X48-D30';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3']    = '13.3R10';
fixes['14.1']    = '14.1R8';
fixes['14.1X53'] = '14.1X53-D35';
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2']    = '14.2R5';
fixes['15.1F']   = '15.1F6';
fixes['15.1R']   = '15.1R3';
fixes['15.1X49'] = '15.1X49-D30'; # or 15.1X49-D40
fixes['15.1X53'] = '15.1X53-D35';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show rip neighbor");
if (buf)
{
  if (preg(string:buf, pattern:"RIP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because RIP is not enabled"); 
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
