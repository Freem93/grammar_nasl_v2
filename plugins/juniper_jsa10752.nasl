#TRUSTED 4fc3f97b40df84bd236dc4104eb321c11f6ab79603dba6faf8a454267c589a6ce37c4fae1b1e62b7fd0fcb35791af0d12ccd341b0c7018be73999cbccd91f179a3feb4e30d826c9e8be790f443d77897f5f770d7db09e222fd39e19e3bba762444b865462dca83677ad11c359e7a37bd5e828de721ae0caa4aa299581131a1cd2bf74217ffcac81488285f527347ff58743b17db5fccd515c6af44efae4d460af5d1ceffe8a23c44b17e58182e81e7b68be0af44a7cd2e5d685be628f82d275f5526a887a43c00327a3ccb96ea5f1f7359aa332884dbbc74ab6adaea25c6148021391f61ed1dc95c56bb61c9130d698e541350684f0edc699f1f4d0e84f4bf70a44c039935bc00bd82c258e1904fac4ece8f5b133adfbba78f02d551c6dcf675e1783591d35d228af70c608fb0adccfd271306116af8fbc71e63dc64495ea6f98e8c20ce5c41016edc3b087c2ae482802448d64d30529318e4c12e172f266d29ad08087ce900d66df725340232d188866d687a7cad0fc0d7e24786072f227b4b8a8856a6668333f758c607e4d214ff13903657ffa4f64a05bf29b2d8955de634fdc3b1690eb6a7f0c6c38169f597ea18b9edea287d49102783ea294ae34895516d566aeeb446cb0ec73dbaa95400978c81f195e26660e3c825bf88b3cd7eb0ec5b2666901f8c8dc32f9c8712332ce1d44de863e4cc214f29f7d28725a1f8647c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92520);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/27");

  script_cve_id("CVE-2016-1277");
  script_bugtraq_id(91755);
  script_osvdb_id(141468);
  script_xref(name:"JSA", value:"JSA10752");

  script_name(english:"Juniper Junos Crafted ICMP Packet DoS (JSA10752)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability when a GRE or IPIP tunnel is configured. An
unauthenticated, remote attacker can exploit this, via a specially
crafted ICMP packet, to cause a kernel panic, resulting in a denial of
service condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10752");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10752.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

fixes['12.1X46'] = '12.1X46-D50';
fixes['12.1X47'] = '12.1X47-D40';
fixes['12.3X48'] = '12.3X48-D30';
fixes['13.3'] = '13.3R9';
fixes['14.1'] = '14.1R8';
fixes['14.1X53'] = '14.1X53-D40';
fixes['14.2'] = '14.2R6';
fixes['15.1F'] = '15.1F6';
fixes['15.1R'] = '15.1R3';
fixes['15.1X49'] = '15.1X49-D40';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show interfaces");
if (buf)
{
  pattern = "^(gr|ip)-";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because there are no GRE or IPIP tunnels configured');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
