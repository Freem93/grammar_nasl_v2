#TRUSTED 2e315fd409d63540e156630708f307392468aea2e3a0c9890b0d74feb9fc3f7d22b3bd358355f048bf17dcf5451358d9a7a70f25b471fcf536364dcde39a1cfad47c1a2f9c4bd4e06d4f73711f790b094d5f2e3402d8765de3aca60520145cac1810faeb28d93973386987fa1b1b45d92d5e3e1227c1e9cf3de0a18e8d8398597170e347a225e2ad9c6165d19bb93a8c5d17b6e4902cad2e1be9745f036c20868b1c0305132ca410f057519a938c99b92c3897bdae2c897f1c2f03ce85b76d276c306a92d193289f4a3eb8e142434b2f730f396a0d4c8c2d178fe577bf4dcc5cafff0339c798cb04ddf95e20d710d9cb662d8972361eed797ffb89a73d8466cb40191325e83fa6bc06359d7208925b1e712defdd5d5d946a94c46e09313923da1ea3b49fe714c8ea39b88860f2ffd61bb4ea0b1751768c1c73a8f9729486f9cbd55c0d8b0d3487a25d8fd0395a6c78127d5cd502e3afcd6a6eee2a8e4f2959042bbbe71bfacfb7a1ee183c0d7d3117d2348f3b7e47b4ff1357866584c11993ec4bec9349cedde8048892baa9d81cb5c28987a26f4a54bb6a8005d4a54c2b13217a7ef1eaac502ac9bdc4480056deed291881fe7223a4c3b27ce932254f6a5d8babfff3403c324f7bd2b16be3b39fb9d9c0486806f31afccf8593b5abef959f4ad7fc07a264e00354848c6da96630b860e73928376db33272d701e3d38530cb4e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82796);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-3004");
  script_bugtraq_id(74017);
  script_osvdb_id(120516);
  script_xref(name:"JSA", value:"JSA10675");

  script_name(english:"Juniper Junos X-Frame-Options Clickjacking (JSA10675)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a clickjacking vulnerability due to J-Web
missing the 'X-Frame-Options' HTTP header. A remote attacker can
exploit this to trick a user into executing administrative tasks.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10675");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10675.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4'] = '11.4R12';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2'] = '12.2R9';
fixes['12.3'] = '12.3R7';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.2'] = '13.2R6';
fixes['13.2X51'] = '13.2X51-D20';
fixes['13.3'] = '13.3R5';
fixes['14.1'] = '14.1R3';
fixes['14.1X53'] = '14.1X53-D10';
fixes['14.2'] = '14.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for J-Web
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management http(s)? interface";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because J-Web is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
