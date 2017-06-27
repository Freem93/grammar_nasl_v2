#TRUSTED 635ef256c422c185ec4959b04386e3caaae80e5f6ef5ee37e736a4af97ed1eee7da5b5018552ef4d0643dacf5b05710e5e6bfafda39abc6183531596f17031dced8d8e7f14c145ec9e29d011a9b7a34096af9a7861929abf204546a9202a19e7ba4eb4e63cfe01e9a0e6a50010b74458e0714c711aa1f85f467e6311e94fe38e94062cba4a1c4f6931cfbf758e43bfc25441b092f3c2479d3dc5786d2eafd092f4669cde0a2480bff72a971cae163c386d7f52067cd9c5c3d0ade654c988606c8856db35a4fc6edb74ecc6ae3efe3a6193388811b580b87da5e5150bcc8c17ee7e168448aaeaa051f19f27644db32c368ad816b35a71f8672fedf5d7025862093a64d2b7884eeb055141a6e813d7c1cd43d451d98572504b549fcaaaf89fa9da8146e3088afe144c993fb28edecd6a0b54d15d7f8bb2e08b8c033227b8dbbd4781d993df2516eb8bc70d91d7fff18f9cbbdd1a2f8e87b2beed64e5116d17c1bcd93fa114ef9765679e27d0d0d97aaa07dac7e1592b969f5d187b20edf757abeed1d4bf60dc6eb3d899d73202f2a76b8b3a19049cbbc1c43beb5475d211f17ebe5926c6d9835665b619abf472b59a3d622776005a06815fbdeb791a9639ddba99e783f0f7f4b7e08b767316fa3f51f4dec11026a82467554c15c5afd8361a7acb066aab68b5b97b72cd219ddf6d64e28236088d0a5841de2fe3217841436057af
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85228);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-5360");
  script_bugtraq_id(75720);
  script_osvdb_id(124297);
  script_xref(name:"JSA", value:"JSA10688");

  script_name(english:"Juniper Junos IPv6 sendd DoS (JSA10688)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability in sendd
due to improper handling of IPv6 Secure Neighbor Discovery (SEND)
Protocol packets when the Secure Neighbor Discovery feature is
configured. A remote attacker, using a crafted SEND packet, can
exploit this to cause excessive consumption of CPU resources,
resulting in an impact on CLI responsiveness and the processing of
IPv6 packets via link-local addresses.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10688");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10688.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
fixes['12.1X44'] = '12.1X44-D51';
fixes['12.1X46'] = '12.1X46-D36';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3']    = '12.3R10';
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2']    = '13.2R8';
fixes['13.3']    = '13.3R6';
fixes['14.1']    = '14.1R5';
fixes['14.2']    = '14.2R3';
fixes['15.1']    = '15.1R1';
fixes['15.1X49'] = '15.1X49-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for neighbor discovery
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols neighbor-discovery secure security-level default";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the Secure Neighbor Discovery feature is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
