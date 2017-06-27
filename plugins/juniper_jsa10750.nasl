#TRUSTED 12cbd3d0920263f0a56f14fe553f4d47eae904969ffe633cd5d7bc4409874732168375050f9ea4846ab19400edf70df3327cfc327d4ff0fc97cbb6ca34dd79678d54c512c99cd4e571180e14667c2920b1da1c4a891b5ff008f50537362cfed974b0617f5e3a1b01a28e085d084313271b17166d1c8c36e3e33b4a65b9a5602387e3b598a8e04797855fb93baafaffb1d3f218e1e2842b9c4136cdcab137be10ccae1cbd8ff57417c84db44c54734399bcb072ffa1ab57424a109a525f20b6b40f1008e328d38b5ee624e2ed5d70692cb4f57a2ca3ff1c6e82e0c9095e56d5970e30adc8b3b7c2682eec334cdc609e8dbef069a77ddf6b8c3c0c70143f16f889372c11c6803323fd2644d64b33d6af39145e97819d00f571997760581fd9c37f546de5826707591c7462359ae11c83a4e5f4e7ce43d1b652b14bbcdca73be20c1cc38a94b1bca6678ec6b9e5b98cb839d185955dcd135e2840beec743d25676d13c55c9de6c41c5745a54a67142be55bfa09e4829441b36353f64315e82e43bdb4b3952cef248c97a43218dd503dc68ed9d57dc1ee3c34fef100e9956835223d86e294d9095faeffa01fd7ecc79fb83a8e69c3d0758ad733608575ab73abfb13740024e188237b12b76285aab7fb29cae951d13160500799e559c8ec73bdd0ceb0450664684a6085db48ad4b84838efaae1676b4c480edc317565b3499d19b4a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92518);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/27");

  script_cve_id("CVE-2016-1275");
  script_bugtraq_id(91758);
  script_osvdb_id(141470);
  script_xref(name:"JSA", value:"JSA10750");

  script_name(english:"Juniper Junos VPLS Ethernet Frame MAC Address Remote DoS (JSA10750)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability when VPLS routing-instances are configured. An
unauthenticated, adjacent attacker can exploit this, via Ethernet
frames with the EtherType field of IPv6 (0x86DD), to cause a denial of
service condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10750");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10750. Alternatively, if EtherType IPv6 MAC addresses are
not required, configure a VPLS flood filter.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['13.3'] = '13.3R9';
fixes['14.1'] = '14.1R6-S1'; # or 14.1R7
fixes['14.2'] = '14.2R1';
fixes['15.1R'] = '15.1R1';
fixes['15.1F'] = '15.1F2';
fixes['16.1R'] = '16.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "14.1R6-S1")
  fix += " or 14.1R7";

override = TRUE;
buf = junos_command_kb_item(cmd:"show routing-instances");
if (buf)
{
  pattern = "^instance-type vpls";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no VPLS routing-instances are configured');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
