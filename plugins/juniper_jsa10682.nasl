#TRUSTED 904294080f4c676f48db232f2609b9144b1fb53f99356a0d15c00618ee31a783f82c6177a6cfd901cd0df3c684d26e240ce755cc93ce104fc4d88b9ee661bce39d33ea7364c34bccf59ed9bd22a15fc39ece4b7bd7563f3ab273d1f1d9f62c4182d3968264953a00b2e51d4b6d4772e82b29156dc03c7fbea28548b4718d74aed87943e0b46905f6d290f7400ebb03c79148709455c302187ad80e0d6193375e66b3b97380a656a448b2a1705d128b7c41e315f713ed4176ab772fd8ef2d998792d764a23663fa4392f5c47d0ec2dddece38f0ad1be69cadd44f3f68eaf045def231cbad2677813c5d6a0510fc6fb3d842e0c12d85d085d7e60ca02b72b3328ffb68283ad889835a26c07e70e3d7473abd903e9ad3fc0774843cf2d8344b764ca6d4571d95dd0ae0d4fb188fc90334892633d3ba6047383348e7d39680a163a22fe911e9a725236339f2296199254f2d9a70aac9537f33aba1f544519b6cab771437f745bd40051d893700279bbe28d2494213b82a9647c5e7b845cfdc1b88e5b6f7725fae2259c9698cc2e1fab4a0fbf0dcbb126a342f40acb045de05802468a6cfb2b2627e38f991d6f7e1236d44a6cce768427ba19b69cd1288f118f172246ca39713eed388974a11b24bba28e284009991404f1e3e3b2161a26520178d2ef2142fb42e96107a1033044b818580ac6dd9228321a990a1e58d11f43f47632f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85224);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-6447");
  script_bugtraq_id(75717);
  script_osvdb_id(124291, 124292);
  script_xref(name:"JSA", value:"JSA10682");

  script_name(english:"Juniper Junos J-Web Multiple Vulnerabilities (JSA10682)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by multiple vulnerabilities in the J-Web
component :

  - A cross-site scripting vulnerability exists due to a
    failure to validate input before returning it to users.
    A remote attacker, using a crafted request, can exploit
    this to gain access to session credentials or execute
    administrative actions through the user's browser.

  - A denial of service vulnerability exists in error
    handling that allows an attacker to crash the J-Web
    service.

Note that these issues only affects devices with J-Web enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10682");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10682.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  
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
fixes['12.1X44'] = '12.1X44-D45';
fixes['12.1X46'] = '12.1X46-D30';
fixes['12.1X47'] = '12.1X47-D20';
fixes['12.3'] = '12.3R8';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.1'] = '13.1R5';
fixes['13.2'] = '13.2R6';
fixes['13.3'] = '13.3R4';
fixes['14.1'] = '14.1R3';
fixes['14.1X53'] = '14.1X53-D10';
fixes['14.2'] = '14.2R1';
fixes['15.1'] = '15.1R1';

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

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE, xss:TRUE);
