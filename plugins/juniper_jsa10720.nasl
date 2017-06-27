#TRUSTED 68d99497aa92677346644d7bf07c5534b5c173ea659832a38d821b19c6dfdbaa868361f24b04a9708fe665f49ffaeb6240eaa2ea938af31f83679d7b7bbfb77fab87d39b2da15c4d046aee1bff6a95fdafc170402f2bb67b6cf1abff1ca5cec4d829588f9d2a7ec8ca0c4aea0ff2700c9415161c2434199ad2ee9493018c09c9c82efa4edb15dead8c115026b9029a538e62bd548069be87b1359a17af562edaa014c75fae904bab4e6cd9e03ea27606eb9d0a25b19ae96c8ed84e695d0a8ee58475589ca7d3c75e770820b26da5b516b54a2bcbe914b15d240c4379d41a5974b8d7f004740fcb7be8687ccc72e60964ece24bb38cd7da6a9712659b22bbeafcd6463e7561e90a24dcc1f86af86464dd2be5cdd8eb3338b3f5736d4f1e2fd4387065570814ac653218812c90d6c7881f8e72b58a53a35f53bf8fc958204e7aa70552fcb60ceb42c1257be5280d9d241a5ef4ab8ab4922a1f350168bcc0efd4767b32e173f509487b76f1ca2c764cc71efdc3169f7544f2d0e1459e61c6050051c995ee333459d8c0053f52550644930e7ad7816090b5c2a0504008a48c393d24bec4d94022b08fa67062a53416194c9f2711de0cd0278bed45cee4632687291614016c882134f2cb496540c8d3f94c9dc194ef488c6d3cb78c2d7cb5c09760b8ba363b53660fa154155428ef097ebd24e585159284d933f0125230fcabcebac0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88095);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2016-1258");
  script_osvdb_id(132866);
  script_xref(name:"JSA", value:"JSA10720");

  script_name(english:"Juniper Junos HTTP Request Handling J-Web DoS (JSA10720)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by denial of service vulnerability due to a
flaw in the Embedthis Appweb Server when processing malformed HTTP
requests. An unauthenticated, remote attacker can exploit this to
crash the J-Web service.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10720");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10720.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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

fixes['12.1X44'] = '12.1X44-D60';
fixes['12.1X46'] = '12.1X46-D45';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'   ] = '12.3R10'; # or 12.3R11
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2X51'] = '13.2X51-D20';
fixes['13.3'   ] = '13.3R8';
fixes['14.1'   ] = '14.1R6';
fixes['14.2'   ] = '14.2R5';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.3R10")
  fix += " or 12.3R11";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the web-management service is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
