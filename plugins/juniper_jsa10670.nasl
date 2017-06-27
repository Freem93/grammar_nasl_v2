#TRUSTED 588d93e5609c4e4294610ba6a6b56548a56b7e4fc20b0f2aca484abfeb1de86dad5db2ee560ed6343f4b6319d7c67e6848974c6f7f3c17442017d7ab3e2a8f6970da4f13415b17dfec05e27e930adc39e56da00f99baf6408d6611939f5bd57bca652e50da177eb4754c84204971d20283252b53477c079296a43e698f5fa64c6bd3925c76b1f51324e0300b74e340681ced23150a2feab84c420733c5cf58b1d296599b65f95b201e89f8170ac83b2aaa01cfd8a7a9bc25a80b5af58b22a2b82f665623c76dca3ad69a82cc665f43f2d8347dc888731a6ba9ec29e3114ec1c1d0c13b8290cd3c791db9500feeee4353dd5d4dffda3a47e684b4fa4db5ed2b84e3de4c86fd0eaf2bd6759f9ab502cef351efd41be8eceeed7d2ade4000285b89ef6b5d56a2fb20675bff8e38e5f0e52eaa1cc63130962244e196b2c4510385ce65bd364d8ec37110364a940b3392eaac4d46d09c6333aa4537305b9c019fcd9db2081ac58e17d39a03f70936840d32f3cc467f7a061d7b3618fbc9825c6e3a16af1cc89e8563ecb706ffcba86d7269012074b411f493c45e0006e4b616aa696c98aefb40c9e8dcd416e4d3e771f0361254c012de2511bb6812087f25e346e3554c8c7466299bd01d80e3109bf589dcf215cb4507e6f4ef97f8e4895a62a2924ab33b606388a43c88ae8cd68772c4d7b671ef18896c93c756f2a6d0d2beb998b1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80958);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/23");

  script_cve_id("CVE-2014-6386");
  script_bugtraq_id(72067);
  script_osvdb_id(117039);
  script_xref(name:"JSA", value:"JSA10670");

  script_name(english:"Juniper Junos BGP FlowSpec rpd DoS (JSA10670)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
improperly processing a malformed BGP Flow Specification (FlowSpec)
prefix. A remote attacker can exploit this issue to crash the routing
process daemon (rpd).

Note that this issue only affects devices with BGP FlowSpec enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10670");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10670.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4']    = '11.4R8';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R9';
fixes['12.3']    = '12.3R2-S3';
fixes['13.1']    = '13.1R4';
fixes['13.2']    = '13.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.3R2-S3")
  fix = "12.3R2-S3 or 12.3R3";

# Check for BGP FlowSpec
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols bgp group \S+ family inet(6)? flow";
  if (!junos_check_config(buf:buf, pattern:pattern))
     audit(AUDIT_HOST_NOT, 'affected because BGP FlowSpec is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
