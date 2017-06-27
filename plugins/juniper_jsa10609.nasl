#TRUSTED 9334ed475107977b156b38a324dc07ff8c97312bd0189057ae77a0e60f2aae1809270b659ec5cf6b0002931bdebb8309ff5c240f7085aa866c1b3253c39a5206848e5d0903588bd8373635f1650a71a4ea75b0386af51e18c60042e590b7cd9999b581d359c8add12905c71edcce1a66d459d96897e170907a37ae516892b294764aeabae2ad7edeffd2a29427cecea5e643367215bd8174e1ca16a350d97263043ae07f38a33ec96345ea60b86db84bf8638d19af76f6483793a99b225360f9495e253307a9abbdd7b3862d2ef987cfcfb5c21eec74ccd3ff7e8efca3dcd40954f462cfabdc4e2968f1f0e7994028f9e61c25b070151957b7c2f36b654a012ab3c56f8ba3ec7a2aedb933d1542fe1e55a79dc26f37ef703cae16f3fdc52f7cef1e30653bb80395f8655875d24b5ff6066e123dd3e0331ca40ebede254559c53bbf5d6456ab66d1050d35337101d4a95f1220024b4e4b59e9d35f25da045d8f36c822f7123c0c9a877d1408bfe20cd1a8fe19627835b35004e1a7484816e4d4031421342daa6a66d66a066824c03b95ae9f73a2839b7193e8ca2c47155ebccf2ca5a72af5059c67461c4f8ef48bfacbd1b281f601dd93214bfe20e7cd536ec7889b1afb846bd299fa99c11f0a980b514a41e8a9cfdecc2564a2967c8e312087a0673889b8e3c3772d5007cec4e14cb1665d056de5224cfbb617924796405306d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71998);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-0616");
  script_bugtraq_id(64766);
  script_osvdb_id(101868);
  script_xref(name:"JSA", value:"JSA10609");

  script_name(english:"Juniper Junos Oversized BGP UPDATE Remote DoS (JSA10609)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. This
issue exists in the routing protocol daemon (rpd) when handling
oversized BGP UPDATE messages.

Note that this issue only affects devices with BGP enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10609");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10609.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/23");
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

if (compare_build_dates(build_date, '2013-12-20') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '12.1R8-S3' || ver == '12.3R4-S2' || ver == '13.1R3-S1' || ver == '13.2R2-S2')
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

# BGP must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show bgp summary");
if (buf)
{
  if ("BGP is not running" >< buf)
    audit(AUDIT_HOST_NOT, 'affected because BGP is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
