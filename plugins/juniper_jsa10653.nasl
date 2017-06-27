#TRUSTED a9a8ffe69b5e1743413ac26398d770ef631c915855ffd4492a5ccb4f757a255c88a6cc19ae3abdfe917c5c8b3d4b4f78ffed50b00087875b6be7c89f50c44aa1e29a0ad618d0efcfe936091039f895b52959598f77dd3ddc1239abe3388bc57f6997339e42a7c0feda4ca45e726d555f5d7dd7e751ef406d7776629c13a3a2a6683f7852008611c0ea33dc5d4865a87b03ef64ddf3d1741bcd83256c08dc1658c879182a9797c1b4ce0edf240579b1d4065ac8a178697fc94317bad65c02c9b88e8503e848370a2cb175c51e7243775568abbf2c878e59a2eae5959b737ed0a754819b38ba05c93265623f4b12c60c2f5d4934482e0f972cf2a2d95ec4f08743922ed5eec1310601513ab180c0b1a8f0118fd07f4df4c8a64f053a1c11f84453a7e1aff1358b37e993bfdaedd1481cec838c00facf6316d262c61c70ee4b6a2ddfd2c04821543dcf2415061dcee2fc6d8124d4d01f4529dd3bccc46ba63efae11fced16547bd582c36532a9ec871bdb13e5563470c6d50a8e92a64f5c4aa53eb55840f01de421629d7c99d2ff82eccac9e0e8f9b550e76e9901ee07dfda39863b32e7cfcce1a70dea53bb3e32c5e88a6fe40b91da834b853c773855795d2d335c5cea537673f842fd04031b4619e1e152f73dfd773e21ce3b51e16b4437da8d3c8c52f3056361199965d5d3208d53d529c47a710e6d5461fdcaf93fc49f53ce8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78424);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3818");
  script_bugtraq_id(70361);
  script_osvdb_id(113081);
  script_xref(name:"JSA", value:"JSA10653");

  script_name(english:"Juniper Junos BGP UPDATE 'rpd' Remote DoS (JSA10653)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
improper handling of BGP UPDATE messages using 4-byte AS numbers. A
remote attacker can exploit this issue, by sending a specially crafted
BGP UPDATE packet, to crash the 'rpd' process.

Note that this issue only affects devices with the BGP daemon enabled
and support for 4-byte AS numbers.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10653");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10653.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1']    = '12.1R10';
fixes['12.1X44'] = '12.1X44-D40';
fixes['12.1X46'] = '12.1X46-D30';
fixes['12.1X47'] = '12.1X47-D11';
fixes['12.1X48'] = '12.1X48-D41';
fixes['12.2']    = '12.2R8';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3']    = '12.3R6';
fixes['13.1']    = '13.1R4-S2';
fixes['13.1X49'] = '13.1X49-D49';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2']    = '13.2R4';
fixes['13.2X50'] = '13.2X50-D20';
fixes['13.2X51'] = '13.2X51-D25';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == '12.1X47-D11')
  fix = '12.1X47-D11 or 12.1X47-D15';
else if (fix == '12.1X48-D41')
  fix = '12.1X48-D41 or 12.1X48-D62';

# BGP must be enabled and the router must support 4-byte AS numbers
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set routing-options autonomous-system 1.10";
  if (junos_check_config(buf:buf, pattern:pattern))
  {
    # Check if BGP is enabled
    buf = junos_command_kb_item(cmd:"show bgp summary");
    if (buf && "BGP is not running" >!< buf) override = FALSE;
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because BGP is enabled and configured to 4-byte AS numbers');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
