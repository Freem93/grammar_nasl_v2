#TRUSTED a888dab428abf12263dcdd3159aa94be42c03b2dee87aaa674e0752768d4dbd3676ea7d26c554290714182680e67717b98eb59f91ba0e50b45f67394ef73d8ed95a52bc2d1e5f9ae1949ec1e7423c4f01d85ec426a6e86a51f6d72b52e18a541754d3e1e5fa3de2adfdc93f654c787f4723084eff7c2e026a4168998a014727c50872a5a49127ba76c47944bc26ee127cb3fb003be7aed713d4cc4cfbb95c2bff3af9c55acb66763e5d63f9845f0c8c3096043cfa1535120c6805cf64fa421b268de21aae5bedb813845ad368ce4ad4938d4e9520b2637e3a5a3bcf94e4cb636be50c5933468ceea5e9c213c136c76d41408950f68baa13719b2a558fce3448daf314efdd299995cd3de97f193d59ca68c5237bc513c3c944a805a0861442215c76f1a483b2dd741cf2237a9e2465329c125e2b6337696815549775c1440ea2bc417eeb5f95ef13130ab24c2ff7cdb1753846e320304b7b542dbb07bffd96db9a4bc5ba3222078b0478599d7413d2eeced7605f1a58e666d59aeb93688cc1fafd47d48839bfe2dd78a247d0f1b070689162350713bbc172fadbe709f0d84e187b8088b00866b98c274500ecc6a9260b29f14931f788852dfd5bbd54dcf41b106f3f244dbc192b4ae602a4eb8c27a6869af6ddfb76bd2e64542011508229d3c117b6d393cfc3c2989459589982a8c555693fb5e5b5ed4582dc547cf8346c9ebfe
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71996);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-0613");
  script_bugtraq_id(64988);
  script_osvdb_id(101861);
  script_xref(name:"JSA", value:"JSA10607");

  script_name(english:"Juniper Junos XNM Command Remote DoS (JSA10607)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability related
to the XNM command processor. A remote attacker can exploit this to
cause a denial of service by sending a specially crafted XNM command.

Note that this issue only affects devices with the XNM service
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10607");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10607.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-12-17') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '12.1R8-S2' || ver == '13.1R3-S1' || ver == '13.2R2-S2')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['10.4'] = '10.4R16';
fixes['11.4'] = '11.4R10';
fixes['12.1'] = '12.1R8';
fixes['12.1X44'] = '12.1X44-D30';
fixes['12.1X45'] = '12.1X45-D20';
fixes['12.1X46'] = '12.1X46-D10';
fixes['12.2'] = '12.2R7';
fixes['12.3'] = '12.3R5';
fixes['13.1'] = '13.1R3';
fixes['13.2'] = '13.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# XNM Clear Text or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services xnm-(clear-text|ssl)";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the XNM service is not enabled');
  override = FALSE; 
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
