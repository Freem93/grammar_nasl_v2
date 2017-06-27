#TRUSTED 5b40bd8fcc192c1494a053fa4a3525c5375a1f4bad3dac667aabf14517ee09ee44bc537c5f9228ddccb1c2c9397f34de212b116df1cc9a55ae494e816766f247a2e1b48f35cc60a4088a6252e8aee0007c006f702cde60ccd4e0d302f413ee60bc70b708f49678dbb45ea159f2374f1e59cee990a08a7dc53b2d8232c9f733a6f68ed01d6f84e7e8e79dd32e8b59f6b7db543301cb0fe3dfc60b16649ed007f111bf832b433cbc7cad161963547b394bc1a214f93d15468392acc3a38af92ea6fa702bb4568dd4c804eefee261104311a56de38e284a4f1dbf538480dbf3ef1a56db50594eaea72ee825e21bab42dcac8219ec685f8b10f5b1c02debed2cced8cca9fe63ce4ab0418385def160b857a16ec3e41e7c785110d7bfdef103ed64a6ce417ae237aaac3e22f81fd806730df583d12fd13be1c8b653fa8843b821d65a5318b6374fc6562036b24078fff24f0bce863822929d4f8a6503461c15abd992570f4a7ad249b36c8251ee4991e3bc8e7e0d2e001483de2869d086bae4efbfb47de69d5ef6469e2dd98297f15df7e933023a080870835172117104e69e6cddd2a9e9d206158f02008c37284a0e4e902256dfe8a830faaff75b4f56624232043cc6f1fc85e54305565280dd0817c31cbf88e06a7998fd55565db77eadeaadd70f516b25b343b30f103be396d1e8148776da175105ad93b2eeba4ee2cf7c560aa4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86477);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-6451");
  script_osvdb_id(128904);
  script_xref(name:"JSA", value:"JSA10700");

  script_name(english:"Juniper Junos SRX5000-series J-Web DoS (JSA10700)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX5000 series device is affected by a denial of service
vulnerability related to the J-Web service. An unauthenticated,
remote attacker can exploit this to cause the system to drop into a
debug prompt, effectively halting normal system operation.

Note that this issue only affects devices with the J-Web service
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10700");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10700.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

# Only SRX 5000 series
if (model !~ "^SRX5\d\d\d$")
  audit(AUDIT_DEVICE_NOT_VULN, model);

fixes = make_array();
fixes['15.1X49'] = '15.1X49-D15';

# Specifically D10 to D19 of 15.1X49 is affected
if(ver !~ "^15\.1X49-D1[0-9](\.|$)")
  audit(AUDIT_DEVICE_NOT_VULN, "Juniper device", ver);

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

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
