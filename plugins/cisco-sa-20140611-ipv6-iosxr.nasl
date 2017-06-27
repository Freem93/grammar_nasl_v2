#TRUSTED 1d5f4a8377c48f77399954c8b58c0949f7a144c258b489963d48ab1b86e931dd38d120ad0182ebb06665e696f2a49ff1f7665b01860e3952f2313414969f61d8d1486fcc70a6e23f7e3f2cbe4df38ec2834a08a36aad0ca9f446de2389100bcdb7ab8aa0fec470294912a7a302591a2a6a4df071e3a2bcd3ceb185d9fe017fdc9b3712479fd6bddbb39623c9c3d4aff1e2d1c97f89100cf0957e27d7d54519d016e0f95a41be1e3ea48d0cf6e4f46e16c1d0924d20b4d3a05a4459870d8e446811a158130a4a89e116fe17c3b21d9bf662bc8d6f92f4918ba41b0accd56095626d17859bb3d010ad6e3c0bb26945bc9511f667bf39e06e8a64f18c4c11ce85dcdba4b5ba13a1f8a86450a2c4f0c6a382da3a635d0efe7cefbc2de288bb8bb848ebc128a4ee05eed90d5e4ad10d6ab8aad0bd842e0e4e8af0c59f15bb40e7e5cbea9b859df121fa1ee1b0be563232d5bb960ae7dacb1f683d1826d81d03f12b55119c5d865edb619d7f5e405f321469e84701ba7d8e91856aa5bcc834a50280725fe2b69417467ffb290be8a0080b864e028a06768e29dbe06ddf39c0d8f9819a4d11b06fb133f56e977e8e82482923d33df62038487be480e88b28def71dbec9d819426af39d845c933fb3164cc8610e45023b98b5f275aac59b9ca00bbca9593a8f99286d1658d760d6ffb9fcf2e702636f61c60062daee71c30b6257ce50ad
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76312);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2176");
  script_bugtraq_id(68005);
  script_osvdb_id(108002);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun71928");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140611-ipv6");

  script_name(english:"Cisco IOS XR Software IPv6 Malformed Packet DoS (cisco-sa-20140611-ipv6)");
  script_summary(english:"Checks the IOS XR version.");
  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XR
running on the remote host is affected by a denial of service
vulnerability due to the improper handling of IPv6 packets. A remote,
unauthenticated attacker can cause the device to lock up by rapidly
sending specially crafted IPv6 packets.

Note that this issue only affects Trident-based line cards on Cisco
ASR 9000 series routers. Also, if IPv6 is not enabled, the device can
still be exploited by a host on an adjacent network.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140611-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46f32f69");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33902");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140611-ipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# check model
model = get_kb_item("CISCO/model");
if (!isnull(model) && model !~ "ciscoASR9[0-9]{3}")
  audit(AUDIT_HOST_NOT, "affected");
else if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "affected");
}

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

# Patches are available for the versions below
if (
  report_paranoia < 2 &&
  (
    version == "4.1.2" || version == "4.2.1" || version == "4.2.3" ||
    version == "4.3.1" || version == "4.3.2" || version == "4.3.4" ||
    version == "5.1.1"
  )
) audit(AUDIT_PARANOID);


flag = 0;

if ( version =~ "^3\.[79]\.[0-3]$" ) flag++;
else if ( version =~ "^3\.8\.[0-4]$" ) flag++;
else if ( version =~ "^4\.0\.[0-4]$" ) flag++;
else if ( version =~ "^4\.1\.[0-2]$" ) flag++;
else if ( version =~ "^4\.2\.[0-4]$" ) flag++;
else if ( version =~ "^4\.3\.[0-4]$" ) flag++;
else if ( version =~ "^5\.1\.[01]$" ) flag++;

if (!flag) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

flag     = FALSE;
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
  if (check_cisco_result(buf))
  {
    pat = "A9K-(40GE-L|40GE-B|40GE-E|4T-L|4T-B|4T-E|8T/4-L|8T/4-B|8T/4-E|2T20GE-L|2T20GE-B|2T20GE-E|8T-L|8T-B|8T-E|16T/8-B)";
    if (preg(multiline:TRUE, pattern:pat, string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco Bug ID      : CSCun71928' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
