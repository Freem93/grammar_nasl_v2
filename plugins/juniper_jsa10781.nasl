#TRUSTED 75228eae18a8c985a1aa8a4deafcc91e2e0c0670e24b8b2ff0a1f0c029014c3280a605791f770f89b20018df071e8665448f3e5afca40bdd4270877f87f68a481b7f7ccd915ece7a6c2c0ea90c01c72c49fd4051ac2ec53ee6bce62f464708c173848cbe84f2124f4c9a8721e32dd714affd36e983c2945a0959e630e96dc33c4cdafb8d379b68909d71dac1f030cdac30af127efd35ed3913620f435afe5b3f17a95cc31db0e70e346b3fa1197868620a6ce26ffbd69063424bc0598236b0895f65aff83e1080c396486f8e06dfe2b7d9d56df3067ecc990a28122122784a44671893b03fd386ec9803f3f6c0ef6c20bc36dd225c78ebfdb4d7d5cdb94865f1852a3922d30e5ef83b509cf3301bf84dec2e114aefddfbca72df08b9b11ace919e30854361e32db26425ffbcc53053739ff599a9a729a9efae8dc4775e398d63ebc53b525143c9e6850285db1439e45155ae8916dc2fdbd64bc70b3aa76fa8bf4c953ec3a30f0c29ea5301c76229dd31721d7b5eea645ff1cc8303204c02258b4a0a6be842026dbe062f4fbafe6c46c90418ac189f55d43557b0961e86d986d68becace6c113b07b28e68b504f2e18be7d1a6bc43938925b9eddb506d1aeba5ca9af93dfe65ca667837657463b54244137cb29a7587a9378552b2988b49d55515009ca2ce76584f0a7158e9f57c25327201a1afd3d8c760f01c4e07db7a91186
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99526);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/20");

  script_cve_id("CVE-2017-2315");
  script_bugtraq_id(97615);
  script_osvdb_id(155440);
  script_xref(name:"JSA", value:"JSA10781");
  script_xref(name:"IAVA", value:"2017-A-0121");

  script_name(english:"Juniper Junos for EX Series Switches IPv6 Neighbor Discovery DoS (JSA10781)");
  script_summary(english:"Checks the Junos version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Juniper Junos EX
Series device is affected by a memory leak issue in IPv6 processing
when handling a specially crafted IPv6 Neighbor Discovery (ND) packet.
An unauthenticated, remote attacker can exploit this, via a malicious
network-based flood of these crafted IPv6 NDP packets, to cause
resource exhaustion, resulting in a denial of service condition. Note
that this issue only affects EX Series Ethernet Switches with IPv6
enabled.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and model.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10781&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae19d456");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10781.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^EX")
  audit(AUDIT_HOST_NOT, 'an EX device');

# Workaround is available
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['12.3R12'] = '12.3R12-S4';
fixes['12.3'] = '12.3R13';
fixes['13.3'] = '13.3R10';
fixes['14.1R8'] = '14.1R8-S3';
fixes['14.1'] = '14.1R9';
fixes['14.1X53'] = '14.1X53-D12'; # or 14.1X53-D40
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2R6'] = '14.2R6-S4';
fixes['14.2R7'] = '14.2R7-S6';
fixes['14.2'] = '14.2R8';
fixes['15.1'] = '15.1R5';
fixes['16.1'] = '16.1R3';
fixes['16.2R1'] = '16.2R1-S3';
fixes['16.2'] = '16.2R2';
fixes['17.1'] = '17.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_WARNING);
