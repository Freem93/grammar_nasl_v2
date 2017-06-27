#TRUSTED 20df9135edce306c64d5cce1e4ba4ae47a82b6743d4e0be63c856733600448fa6dd8b0d0bc1ea01b6290695046e895283120fc0f082752df89657dd189b571f91f53c7d1a81f5ad2df4fd4dbfdbd6b46773916e480fc66b79745b5c3ac2c6db9e8e5da89c18983273a2cf668a5c081bf940e77e5b5c020108610971df1fdc7167b4f36d41f6dfd486ecb0057b7de11da4a647c30949a8e67dc9b3cf91efe20ab6e9d23408e44da222276dc21c1fea4b698f2c0f5386ac34bf9c526c9399afebd2ff631c98bcffb4fa8b555379897e34dd5bc5a9cb89d7b880aadacf4fafd7f43abf0b24885c4a72ea2cb0f804b1348c4e81364d8774772e51308e2d4d77cd230ce71e64c60b380ba1801da194f27035df6893dc42bf1b0211917f7288c1cf8c1aa5f5262f65862fbeed7baa2248988257f9da25451c59b92b25056de2c1e340388736a4d403f6c332022c6b326b9356f67e888649d09b595cd1f6a8c57af8bf3a173688855155d4a0eac373889a484b2a906063205afa15b1a89ea2248d10adbadf60bd50512bd267137da25b17873fec505267834741c223979183f97a11d392baea8dc568aa3240d00c540a7a2803c7f548da259675aea90bc8e97837591a90880356e140fe39c736285d1312b1bb3e2508b195efd27867979f7626b31aa6fa7cfecb8cd15544af18040d12b60d19782451def28e608733d61cc24bc929765
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90761);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/07/25");

  script_cve_id("CVE-2016-1261");
  script_osvdb_id(137067, 137068);
  script_xref(name:"JSA", value:"JSA10723");

  script_name(english:"Juniper Junos J-Web Service Multiple Vulnerabilities (JSA10723)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by multiple flaws in the J-Web service that
allow an unauthenticated, remote attacker to conduct a cross-site
request forgery (XSRF) attack or to cause a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10723");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10723.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
fixes['12.1X46'] = '12.1X46-D45';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'] = '12.3R11';
fixes['12.3X48'] = '12.3X48-D30';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3'] = '13.3R8';
fixes['14.1'] = '14.1R6';
fixes['14.1X53'] = '14.1X53-D30';
fixes['14.2'] = '14.2R5';
fixes['15.1'] = '15.1R3';
fixes['15.1X49'] = '15.1X49-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the web-management service is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING, xsrf:TRUE);
