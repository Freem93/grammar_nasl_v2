#TRUSTED 72b04fb38837a95cd7b1550594f8a8a1957daa88b77c927d711f709107d7791814802ab7fd1d5ae040e34df87f4d3b42816405e56d80ab6e6710d1363afd58fb35d647753545483de6b74498106e3c230ad2d9f792380487ca1aa887e9a79fdd87b481c7015f84bf1ad5dc4170f6ad4bc3c486fa140f43f29c9a85507144783c972ccce179229d170e1a0e019f406c2844f870d4b2097c7c576a683b78af0ca7ad31aa5f445620ba47def5a154bec4ed0d7676abf7c9559f78411288fa3dc91e426fc4b88f36e47fc05b9db0daf3ac7e66cdc10bcbc28eb44724678fc4b55b77661b925069fc79e54a7aaf3bb14a3371ce94bf1b9cf5b3815726af50e4f7e5e55294ba813671f68a7ee239da23e1bb0f7e2df52207f7b1bf991b0903a3e300593dc3fe242385285468b0eec493ab48c0f828560d50dead5f5170f087597f86a78bf234391272c5edc2576512d9fca978bcf145f787283fdb3211013c4d83fac6d7db15133c9d61f5c0c65d0b30977b9499f55d2e3a2927c4ad3eb71daa3395f09787052522cb236f6bec0187823e5888b9394174283f677925c2c1ebc23887c89944a34c2109c8d943bdd81ebe6efbf4e312226284324841d7dbcbb2f2f4a481f1ac5fe0cdf9e4b799cc1e42523e627bed41e2ec2299c8e6fa28a62771f0e453c3ac3ca08f6ac28ae3dc25cfc342e139a1e0f2723eb9beef63ce524ed2c78198
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73493);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2711");
  script_bugtraq_id(66770);
  script_osvdb_id(105612);
  script_xref(name:"JSA", value:"JSA10619");

  script_name(english:"Juniper Junos J-Web Persistent XSS (JSA10619)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a stored cross-site scripting vulnerability due to a
failure to sanitize user-supplied input to the J-Web interface. An
attacker can exploit this vulnerability to execute arbitrary
JavaScript in the context of the end-user's browser.

Note that this issue only affects devices with J-Web enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10619");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10619.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

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

if (compare_build_dates(build_date, '2014-03-20') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['11.4X27'] = '11.4X27.62';
fixes['12.1']    = '12.1R9';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.2']    = '12.2R7';
fixes['12.3']    = '12.3R6';
fixes['13.1']    = '13.1R4';
fixes['13.2']    = '13.2R3';
fixes['13.3']    = '13.3R1';

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

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING, xss:TRUE);
