#TRUSTED 4f7ff891def0758978c7277d917901798a82a409e4cf3baac45c76bafa5643970a9f36edffd30786ecb48bd9396d0051269a4fdabf2a48afd853f03b5bb840941bd5e0be88eb7b8f92ffbbe8da64730f75fb60eec426eb68c3e550a88d7c9bf7c3a9853166dead5c96b45f89d0e5b251064dc4f3466e469fed3110c06527f8458d5f2fe96ae0224e50445ed13408c017c97478e8ead0d3f9c49c8c93be1b6c9fb906ad84d7dd0c3effa737889d96e0fd61afdb27638f644dbbffd2b25ef4b1c26068ff93b1737662a4d1dd8293e859b7982686e74d09783b543d26073c325799e275f79a61c21ea60e652e5478126b8d3c1b259803150ea2453145daae293078975e142e2d9cc3b957e971316ced1661c6fbb865fe5938f3fb8a42a135eed694be2b8ef9b002ffda2b228372996dc6cd987284470f470d1e38c5f89fc88bfdb897fc0ca6fc3889125c7e099d3b1f7114442893f92d6c0b80d7676fbf2c463ad5be7439a89a69ae0a61c36e4862253910cb17ce0d17c7537c643a7c4c52286f1c1f7a54b6f8cac3da3a1266e7fdbcd5da3d5c92d83bf680576e05f6ac9c8e96cbcbe27971670e6552ccc001d583f3b238cf14f44644b96741228bbb15b7be9b5a60fa8f3477ff5da883698db649ee697c5290a1fb7f01662fe3c1197c7f2967238163963ab4e9fe87a569c1629a3ee1374390d43906e6c64829a861cc459d0901
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70475);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-4689");
  script_bugtraq_id(62940);
  script_osvdb_id(98325);
  script_xref(name:"JSA", value:"JSA10597");

  script_name(english:"Juniper Junos J-Web CSRF Protection Bypass (JSA10597)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device has a cross-site request forgery (XSRF) vulnerability in
J-Web. Successful exploitation of this issue could allow an attacker
to take complete control of the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10597");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10597.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-08-31') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4R13';
fixes['11.4'] = '11.4R7';
fixes['12.1'] = '12.1R6';
fixes['12.1X44'] = '12.1X44-D15';
fixes['12.1X45'] = '12.1X45-D10';
fixes['12.2'] = '12.2R3';
fixes['12.3'] = '12.3R2';
fixes['13.1'] = '13.1R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for J-Web
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management http(s)? interface";
  if (!junos_check_config(buf:buf, pattern:pattern))
    exit(0, "Device is not affected based on its configuration.");
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE, xsrf:TRUE);
