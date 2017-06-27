#TRUSTED 0452c99cee62d58e36258c70a1824982458fe77062858a7b9f2556ea2da46325a5e97f1cabaa506c8c35cd9657a438b6d37e4404d16e44450d351599d04376656283f3b511e78075f42f95ca04434968cac04400aa56ed686bbf586310bfd65ca9ce598a503383e8aa4b635bd588334396dd1af98b8e30139b057160b1a8576c8f911a2c87d55d2238ef552fa93c23df55985d8172e945cdf077e224177ef8da95f29977e001620e8b66f2cbe558c579f5f2fd5ac41bdfbcdb1c230c1e335247045622d7f9217ad88a6d3b76fbb4012530feb37cda5f13dd560d4996c9c78c19cedc9047766b4bc5d36597903e51a3a67e33fa071040e7dacec5530c19aa2afcd93d0c1e1a7f335098f650d7f6b31f1a4c814af80cbe63644e7c7f4ff9fffac7bd4b23f9eed139473496ee1bf272d5fcc147c19b93ba2d5c2c99c7ceecd357c292c0186e4d5589c9c933dce1a8edfcbdc4dffe3505d2df25020fc345d4a34b78a873639680c883b0bb056a8b965278d9ec68b27f4b53407740ba5615305350d5a9c78d6285ad3ba0e7b9653d2fcfb6818a6d096f1f50232386bdab9b791caa2893031067268faac0ff00846df7fdc9c901b3118833c719bec3e4afa828582443f041bc4940a4e734bbd27aed4a8f0a181200461a10e8d9f61938c7393627c4d8cbe121f22535d440ec81dac31811980d501209c56c9cbb1d34980226f60669c3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96659);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/21");

  script_cve_id("CVE-2017-2301");
  script_bugtraq_id(95396);
  script_osvdb_id(149994);
  script_xref(name:"JSA", value:"JSA10769");

  script_name(english:"Juniper Junos jdhcpd DHCPv6 DoS (JSA10769)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the DHCPv6 daemon (jdhpcd) when handling DHCPv6
packets. An unauthenticated, remote attacker can exploit this issue,
by sending specially crafted DHCPv6 packets, to cause a denial of
service condition for subscribers attempting to obtain IPv6 addresses.

Note that this vulnerability only occurs in devices configured for
DHCP services via IPv6 with either Server or Relay enabled. IPv4 is
not vulnerable to this issue.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version, model, and current configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10769");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10769.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(
  model:model,
  flags:MX_SERIES | SRX_SERIES | EX_SERIES | QFX_SERIES | ACX_SERIES,
  exit_on_fail:TRUE
);

fixes = make_array();

fixes['11.4']    = '11.4R13-S3';
fixes['12.1X46'] = '12.1X46-D60';
fixes['12.3']    = '12.3R12-S2'; # or 12.3R13
fixes['12.3X48'] = '12.3X48-D40';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3']    = '13.3R10';
fixes['14.1']    = '14.1R8';
fixes['14.1X53'] = '14.1X53-D12'; # or 14.1X53-D35
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2']    = '14.2R7';
fixes['15.1F']   = '15.1F6';
fixes['15.1R']   = '15.1R3';
fixes['15.1X49'] = '15.1X49-D60';
fixes['15.1X53'] = '15.1X53-D30';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if DHCPv6 is enabled as a server or relay
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Parse interfaces that have DHCPv6 configured
  patterns = make_list(
    "^set.* system services dhcp-local-server dhcpv6 .* interface ([^ .]+)(?:\.[0-9]+)?", # Server
    "^set.* forwarding-options dhcp-relay dhcpv6 .* interface ([^ .]+)(?:\.[0-9]+)?"      # Relay
  );
  interfaces = make_list();

  lines = split(buf, sep:'\n', keep:FALSE);
  foreach line (lines)
  {
    foreach pattern (patterns)
    { 
      matches = pregmatch(string:line, pattern:pattern);
      if (matches)
      {
        if (junos_check_config(buf:buf, pattern:matches[0]))
          interfaces = make_list(interfaces, matches[1]);
      }
    }
  }
  if (empty(interfaces))
    audit(AUDIT_HOST_NOT, 'affected because DHCPv6 is not enabled');
 
  # Check that the interface is enabled
  foreach interface (list_uniq(interfaces))
  {
    pattern = "^set interfaces " + interface + " .* inet6";
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    } 
  } 
  if (override)
    audit(AUDIT_HOST_NOT, 'affected because DHCPv6 is not enabled on any interface');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
