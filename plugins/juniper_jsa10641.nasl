#TRUSTED 88cd1c0325a7fbd241904ec40529336c63c6a6c4a8e145cb04c9412dc8e4676d38ebf7ecece982c5e301ed8a292b4fb364373899cfa267ce272ffa4d87458fdcee6db254eb1547d3807ed2ee4c2d3c41bfdd58cf35601c2d74b2494ca1d9f57f033617e0cc0a31f1018f8a5ecb1f6d57a6c4300245cc8fc97daeeab459864d3ed6fb04c03421f51dbb5a3e410339340c872b231d59af792cd3a636aa2fbb9ec1b16c106c02ceee642c04fc78e8217b02886500755888a9705f8d55236d284e466ed2134deee05ebd365180b5cace0301fde50ca8689f07872d03a0976b4ba55f4d0c65b4e224dc9469fd6c7567cd6472266fa45370ab15d4c6a801b5dd1f79c1f39891c8097a31a7538ea599e1f0062252485197e4779cb27b376ae659f56ecb2784120dc4eba5ed196803cb784738c0769ad0e806e6458a62f46a218e87a86a9f23e8c4f2cb6abf323831e545923fa799c2b27a279c00c19b08d597a917184ebf0d788ebe106356414b62ce761d1d3ca21307ee937bdc533a4ae7b09086618ebbce0b5614377a13dccfe7afebde9c3cbe0ed650d38c1efdecfff9926292eac19bc2989b56e4b332e87a72568eaa1b22ea1c4e1ff136f308f42080a6b01faa0e0f5b80c4086d92927ca55c8e43996db261abc229f74c41bd80257898fe818bd625dd369f5accdde9014e454d5e87604db620473d6b2fef725581a388b44a3b03
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76508);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3822");
  script_bugtraq_id(68553);
  script_osvdb_id(108936);
  script_xref(name:"JSA", value:"JSA10641");

  script_name(english:"Juniper Junos SRX Series NAT IPv6 to IPv4 Remote DoS (JSA10641)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a denial of service
vulnerability. A remote attacker, by sending a specially crafted
packet to an SRX series device, can crash the 'flowd' process when the
packet is translated from IPv6 to IPv4.

Note that this issue only affects devices with NAT protocol
translation from IPv6 to IPv4 enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10641");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10641.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

# if (compare_build_dates(build_date, '2014-07-31') >= 0)
#  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R8';
fixes['12.1']    = '12.1R5';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D15';
fixes['12.1X46'] = '12.1X46-D10';
fixes['12.1X47'] = '12.1X47-D10';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if NAT protocol translation from IPv6 to IPv4 is enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set services nat .* translation-type basic-nat-pt";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT,
      'affected because NAT protocol translation from IPv6 to IPv4 is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
