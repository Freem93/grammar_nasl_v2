#TRUSTED 3ce538120e961d453cfd49558b66666395facdfbb11d1b600049b61a6474d7e6a707822aaf1f9ab0fdf6f2bb9564259e9e67b77c223884c833cb86ae71a8123ed3ee8f9758f429b77b2a439ea4e45d2a2c6af0c9654928556387993dc86fd648758ac429f00986b53f5968abf52e1b76500e3b15d793e67854d574a5a8202e0d5cfe6109d7f8641d249aafe323b0ef27f3c12a7f730b712ad01ed6a9dd8080d4975f5a3ade89e5d3960cbcdcca95a93aabcd06b92aeb559c89a1abd1930726484c3dbc28ab3987eddde3fd1a56b5014430edd5f00891743fdefd0c75213aaf4d30f03fe2c7f2a70817c77edc72e5fa686ef767454c3a22d8c8a833654c0b3e8eea0e603e5915ba0a86e1f91ad1ea5a450148b6b529c3dded4e1a98788a9a843603727505d03475b7f76d3f4d3231920af6154d08602541d50380a010ff264cb7228e473ac2679a6fccdf9187cba67dd47a9f3ccc35881982a0e086a921bd4f617a275bad225ad2c6fb91e6e3e7246ce0ab46ace67c21d123e6defb30caa1cd76e6be654e9c40dfd957a72b4f464db7251c458cfcd207385a16a879954731b7e5531db21c93b70479214e3dd82694e4e5e1836b1f9da46a550681e3c1a18698dcb61630f4ed8839bcad54abadb716a36c39fef1731b372a4371127e0627294b70da3882e1fcc5783ec736155adbaad772165bbf37c639621dddc57c57d9302d9c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86606);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-7748");
  script_osvdb_id(128905);
  script_xref(name:"JSA", value:"JSA10701");

  script_name(english:"Juniper Junos MX and T4000 Series Trinity uBFD Packet DoS (JSA10701)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is potentially affected by a denial of service
vulnerability due to improper handling of uBFD packets that are
received directly by chassis that have the 'Trio Chipset' (Trinity)
MPC. A remote attacker can exploit this issue, via maliciously crafted
uBFD packets, to crash the MPC line card.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10701");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10701.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "(^MX[0-9]|^MX-MPC[1-4]|^EX9200|^CHAS-MX|^MPC[4-]|^T4000-)")
  audit(AUDIT_HOST_NOT, 'an MX Series, EX 9200 or T4000 router that supports Trio (Trinity) chipset line cards');

fixes = make_array();
fixes['13.3'   ] = '13.3R8';
fixes['14.1X50'] = '14.1X50-D110'; # PR1102581
fixes['14.1'   ] = '14.1R6';
fixes['14.2'   ] = '14.2R5';
fixes['15.1R'  ] = '15.1R2';
fixes['15.1F'  ] = '15.1F3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Label-Switched Interfaces (LSI) / Virtual Tunnel (VT) interfaces w/ MPLS IPv6
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols mpls ipv6-tunneling";
  if (junos_check_config(buf:buf, pattern:pattern))
  {
    pattern =
      "^set (logical-systems|routing-instances) .* (no-)?tunnel-services";
    foreach pattern (patterns)
      if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;
  }

  if (override) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

  buf = junos_command_kb_item(cmd:"show chassis hardware");
  if (buf)
  {
    # Trio-based PFE modules part numbers
    #  https://kb.juniper.net/InfoCenter/index?page=content&id=KB25385
    part_numbers = make_list(
      "750-028381",
      "750-031087",
      "750-028395",
      "750-031092",
      "750-038489",
      "750-038490",
      "750-031089",
      "750-028393",
      "750-028391",
      "750-031088",
      "750-028394",
      "750-031090",
      "750-024884",
      "750-038491",
      "750-038493",
      "750-038492",
      "750-028467",
      "711-031594",
      "711-031603",
      "711-038215",
      "711-038213",
      "711-038211",
      "711-038634"
    );

    foreach part_number (part_numbers)
    {
      if (part_number >< buf)
      {
        override = FALSE;
        break;
      }
    }
    if (override) audit(AUDIT_HOST_NOT, 'affected because no Trio-based PFE modules were detected');
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
