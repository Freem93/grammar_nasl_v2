#TRUSTED 2044fa639aa965ca9ca5ff7bbbcc92dc7872d68b3cf6d072e1c1a1230adee6567fbd9f9245d6e5affd77ef595925bdc4479c03201f178eefb0498f3b10b86d93e65fd23ef02b73f43344380e3f323a0c987b23725fe67f81c78cedfa95fbe347fb0783047f2d267ac40636781634276a1e9809196cee70746a232c12bf028f7e80e3821871c288d5526a0c54d726e87858b385ad28884ef113fcccf1e8c81583c92d86646b8aa4debc137c1b0f293d59f5e56f4be146097267f89a231c3c9e91963a959cebcfe8eea80483aeb7bf0c216070efc179e5e3c64cba72367f8c346c11eb5da342157e782aafe9e60d648ef02994d5d913a7cf261a28836551f7eb78c995366ad5abbfbabdd618c650aee1363da6a9539a94fd0291464396fc411d5aa4c50556e7f5f224c561c745d9aab24f3aeaee687c525183a062c8555f29ac510cf871cc341f060fd9c5dd27c03aff4b232e9dbc2c132239ce0d271b53d5815b2c12ed02bdaa9a5a8a35a3330aac3fc4b880337d501c096f469bf7701085d20b8377f599a793f0b793b2cf76b824675034a8902db7dbb11be12a0c2bbda1ba9d9a0b8f8ef4379a28c80e9f4c367f288baee107fc19da636bc29f515a53d30abc510360259c1512be5f57ead3fe4d04fa07ed869ccc3cdf26df311647923a3cc4bd787f49cf55b5c6bd9442f9a60afd001b69625bdebb4040d10324f9766ac966
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99525);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/20");

  script_cve_id("CVE-2017-2313");
  script_bugtraq_id(97606);
  script_osvdb_id(155436);
  script_xref(name:"JSA", value:"JSA10778");
  script_xref(name:"IAVA", value:"2017-A-0121");

  script_name(english:"Juniper Junos Routing Process Daemon BGP UPDATE DoS (JSA10778)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the remote
Juniper Junos device is affected by a denial of service vulnerability
in the routing protocol daemon (rpd) when handling a specially crafted
BGP UPDATE. An unauthenticated, remote attacker can exploit this to
repeatedly crash and restart the rpd daemon.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10778&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?910a6d37");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10778.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
# Commands ran may not be available on all models
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['15.1F2'] = '15.1F2-S15';
fixes['15.1F5'] = '15.1F5-S7';
fixes['15.1F6'] = '15.1F6-S5';
fixes['15.1F'] = '15.1F7';
fixes['15.1R4'] = '15.1R4-S7';
fixes['15.1R5'] = '15.1R5-S2';
fixes['15.1R'] = '15.1R6';
fixes['15.1X49'] = '15.1X49-D78'; # or 15.1X49-D80
fixes['15.1X53'] = '15.1X53-D63'; # or 15.1X53-D70 or 15.1X53-D230
fixes['16.1R3'] = '16.1R3-S3';
fixes['16.1'] = '16.1R4';
fixes['16.2R1'] = '16.2R1-S3';
fixes['16.2'] = '16.2R2';
fixes['17.1'] = '17.1R1';
fixes['17.2'] = '17.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show bgp neighbor");
if (buf)
{
  if (preg(string:buf, pattern:"BGP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP is not enabled"); 
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
