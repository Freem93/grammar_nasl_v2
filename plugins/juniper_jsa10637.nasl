#TRUSTED a2339fbdcbd446dfc260e637e6061707905b4e14d309ef6c6f85aee905ef6572ebd5d301d708b5d98cac22db5a3bf4d74c614926ab4ba79b9779410a04b8fed499fd2b17bc5d6397373eb02049f70385c9f6a734e34d2ad6b14ffd6b1a93fb8ca43861ab0ad0c682e3678b87edcbb9093485b745392d8e3f2eb345a598beea1957774260c3bf60ec1d34d060afb33c473eb1769d4f8cbc0b62ef34841cd34813de32e7b93713f7197bcc0616dc92519f8a8e23df2e49e81499fe551ee05caa4be5650176053d8ea7beed16e6428d88f3a12c52942a3b431a80614b1fc9e48e0d57505410f2bafc4a58e88dd9329906e8c17981e591e16891eeab08c3111f7aeff9cff21aed1738cc3a4e21f27af5dd1e257b64dc643891b325ab922a821bbab64bd143320c397561a9e7e34d9f77af7cc625222231ff016112c572ab223ba77a8ce5863367643135f1e8eeefdf06755422a7fbb9dafb0c289ed7da743d0387952a82470012d4cf3ec536ce872d51384798bed385b7fabd86ee8699f036f62f830ba66b36e8c20dc65bc411d3f9fd3f3c337eecb2d46c175322db90abd9c2d9ab901b5772de2764013c3581112e62281c76bc8a19422413c0a68b3f566a9b30df343425ece7fa0f5b15747559a9375b414600c63b18e3acfab0742ebf7f1e8223b1842720c741626ef36c0b94200745592390f8c374240e3df329614fa7422440
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76505);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3819");
  script_bugtraq_id(68539);
  script_osvdb_id(108939);
  script_xref(name:"JSA", value:"JSA10637");

  script_name(english:"Juniper Junos Invalid PIM DoS (JSA10637)");
  script_summary(english:"Checks the Junos version, build date and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability. A remote attacker,
by sending a specially crafted PIM packet, can crash and restart the
RPD routing process.

Note that this issue affects all PIM routers that are configured to
use Auto-RP.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10637");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10637.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

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

ver        = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

# Junos OS 14.1R1 release date
if (compare_build_dates(build_date, '2014-06-26') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R12';
fixes['12.1']    = '12.1R10';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R8';
fixes['12.3']    = '12.3R7';
fixes['13.1']    = '13.1R4';
fixes['13.2']    = '13.2R4';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if Auto-RP is enabled 
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols pim rp auto-rp announce";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because Auto-RP is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
