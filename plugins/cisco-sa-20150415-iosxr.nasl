#TRUSTED 467d1a006bf6c2895f88ad2c2e0731e00734a8613ce734b28945aed58fd849236076387e99aaf4d62aa1ffd17424a146b3bab22a9d099ec43897e8e4d921a836d3d39d53570e0ab87a1c356d19cfdf4d62d1dfbc7d9bd9e81f0af7ca874a2f64ac14aedbfeed31285c70107fa3ac68fc7b72c597661857e7105a219772d4ea0014ec1f8384fd36f8c7989afcc4a759fdac533dd37e1465d07326d7c5005e75aaca5365ba739b697c6d6eaa3334623accc7bfcbecb6d6517cc821a9215f9ce5b1131902bcec9805787308ab739f991fa285df2d050fd774e37b0160b745856b9f6f04d8812ecbe97140249e3e1c3143a19fd3d64081f8dd70216eb050bb38ba623c6e04fe6832c866b85b7979b8cd427039a6df66b48dd0c3393f575051e92dfa0d3f2dafe3a969c02f18f9f28dde4c643cb413402cb8c721b33f1908c54c7dd1ae7975a8533fe766a27bd724124dc2747c45b21a8b797b58f86689db29dfaa57f41f2ad388062308c3a3c88babc35d3f5906ea070adf3b2c6f476ce71330bec55bad8ec602a9cf435f027d03bab17cd815a5f6460f09e9093c855b9ed762385832fa261c13d8e200fed2ac31d9379b2b66ef694a8e3c53f0e70fbf10a047bda4263dde64fdb67327426712bfda4cde0f897b6fde042035a57d65f92bc1548001b485a3c2a70c73c8882168dcfd96f5b5d291995746cc879e4528c0e61b9e21cd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83054);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0695");
  script_bugtraq_id(74162);
  script_osvdb_id(120786);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150415-iosxr");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur62957");

  script_name(english:"Cisco IOS XR Typhoon-based Line Cards and Network Processor (NP) Chip DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XR software
that is affected by an error due to the improper processing of IPv4
packets routed through the bridge-group virtual interface (BVI)
whenever Unicast Reverse Path Forwarding (uRPF), policy-based routing
(PBR), quality of service (QoS), or access control lists (ACLs) are
enabled. A remote, unauthenticated attacker can exploit this error to
cause the device to lock up, forcing it to eventually reload the
network processor chip and line card that are processing traffic.

Note that this issue only affects Cisco ASR 9000 series devices using
Typhoon-based line cards.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150415-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dfc693f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38182");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur62957");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCur62957.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (model)
{
  if (model !~ "ciscoASR9[0-9]{3}") audit(AUDIT_HOST_NOT, "ASR 9000 series");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "ASR 9000 series");
}

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

# Rough version check
if (
  version !~ "^4\.3\.4($|[^0-9])"
  &&
  version !~ "^5\.1\.[13]($|[^0-9])"
  &&
  version !~ "^5\.2\.2($|[^0-9])"
  &&
  version !~ "^5\.3\.0($|[^0-9])"
) audit(AUDIT_HOST_NOT, "affected");

override     = FALSE;
is_typhoon   = FALSE;
bvi_enabled  = FALSE;
urpf_enabled = FALSE;
acls_enabled = FALSE;
qos_enabled  = FALSE;
pbr_enabled  = FALSE;

missing_pie  = '';

# Cisco SMUs per version (where available)
pies = make_array(
  '4.3.4', 'asr9k-px-4.3.4.CSCur62957',
  '5.1.2', 'asr9k-px-5.1.2.CSCur62957',
  '5.1.3', 'asr9k-px-5.1.3.CSCur62957',
  '5.2.2', 'asr9k-px-5.2.2.CSCur62957',
  '5.3.0', 'asr9k-px-5.3.0.CSCur62957'
);

if (get_kb_item("Host/local_checks_enabled"))
{
  # First check for Typhoon card(s)
  # If no Typhoon card, then not-affected.
  buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
  if (check_cisco_result(buf))
  {
    if (
      "A9K-MOD80-SE"   >< buf ||
      "A9K-MOD80-TR"   >< buf ||
      "A9K-MOD160-SE"  >< buf ||
      "A9K-MOD160-TR"  >< buf ||
      "A9K-24X10GE-SE" >< buf ||
      "A9K-24X10GE-TR" >< buf ||
      "A9K-36X10GE-SE" >< buf ||
      "A9K-36X10GE-TR" >< buf ||
      "A9K-2X100GE-SE" >< buf ||
      "A9K-2X100GE-TR" >< buf ||
      "A9K-1X100GE-SE" >< buf ||
      "A9K-1X100GE-TR" >< buf
    ) is_typhoon = TRUE;
    else audit(AUDIT_HOST_NOT, "affected because it does not contain a Typhoon-based card");
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  # Check for patches next; only specific versions
  if (!isnull(pies[version]))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_install_package_all", "show install package all");
    if (check_cisco_result(buf))
    {
      if (pies[version] >!< buf)
        missing_pie = pies[version];
      else audit(AUDIT_HOST_NOT, "affected because patch "+pies[version]+" is installed");
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("interface bvi " >< buf) bvi_enabled = TRUE;
    else audit(AUDIT_HOST_NOT, "affected because bridge-group virtual interface (BVI) is not enabled");

    # Next check uRPF
    if ("ipv4 verify unicast source reachable-via rx" >< buf) urpf_enabled = TRUE;

    # Next check acls
    if ("ipv4 access-group " >< buf) acls_enabled = TRUE;

    # Next check QoS
    if (
      "service-policy input " >< buf ||
      "service-policy output " >< buf
    ) qos_enabled = TRUE;

    # Next check PBR
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_policy-map_include_pbr", "show running-config policy-map | include pbr");
    if (check_cisco_result(buf))
    {
      if ("policy-map type pbr " >< buf) pbr_enabled = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (
    is_typhoon
    &&
    !override
    &&
    (
      !bvi_enabled
      ||
      (bvi_enabled && !(urpf_enabled || acls_enabled || qos_enabled || pbr_enabled))
    )
  ) audit(AUDIT_HOST_NOT, "affected");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCur62957' +
    '\n  Installed release : ' + version;

  if(missing_pie != '')
    report += '\n  Missing update    : ' + missing_pie + '.pie';

  report += '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
