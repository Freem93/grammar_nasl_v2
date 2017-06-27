#TRUSTED 679932527965daf71847bf66d11e1a45d68309ff1e5e55cfde51e33f0ba952b0fa0627a91790110c2552f1e36fbfa75a583bee7e73df5de60ea4250b81ac2633a2859548aeb108831f8c0f1e6129c4736b2cf17192a4a25c312918962f23e6f1cf651edc24a8762951b64fb97d4355e031e7547f92d622691bc74074531d1cd453ab83ae4bf2db00ff39350fff7c574784b0276b8914c51a8a8a67191262ae948b05c84536da80112a7e5d9c18f491b23d7adaf21e655efbbf6e291d644c5125eb603163b7b797e98c7f595ec11db25fd5acb0a94ab47844c88439ec4296049b9530c517b3b78ea02304539ccd5b5eb1b52330291497076420c67d0a2000e0b3620871ec0127625c35789692703c12d5761e5c3b6b899add1e7ff9eb4a679a4b40b8331fbcdd6a56e272b89a818627c94735c8ceee4f44d6da99d00e375b65c6b4dcd51ab8d62ef0be3eb804d01aa38923eaf33fb9f62a6927030e2fb7e1a821d967ee829ce2aa869bcd2f60eb5048f6011f88ec075ba49be15a01b49a15330128e7f218ea706ee9aa2d5fbe902390839e2e6dca4f02f4403d2ba91e657b24507ecd511d08debf5f13aaaa60c58456168afe2c0b51670f93f365f4386b4d697f0a7c159bb22b37db2ef96441881c8f4c030047054ab80dd53dda596f87ee8b6d5d64d7ab78c1f92c427720666de80c77ceade018d5bde7e62c69d92fd0cc870f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80954);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/23");

  script_cve_id("CVE-2014-6383");
  script_bugtraq_id(72071);
  script_osvdb_id(117063);
  script_xref(name:"JSA", value:"JSA10666");

  script_name(english:"Juniper Junos MX Series Trio-based PFE Modules Security Bypass (JSA10666)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos MX series device is affected by a security bypass vulnerability
when processing stateless firewall filters on a device with Trio-based
PFE modules with IPv4 filters. A remote attacker can exploit this
issue to bypass stateless firewall filters.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10666");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10666.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
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
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

fix = NULL;

# Only versions 13.3R3, 14.1R1, and 14.1R2 are affected
if (ver =~ "^13\.3R3$")
  fix = "13.3R3-S3 / 13.3R4";
else if (ver =~ "^14\.1R[12]$")
  fix = "14.1R3 / 14.2R1";
else
  audit(AUDIT_INST_VER_NOT_VULN, "Junos", ver);

override = TRUE;
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
  if (override) audit(AUDIT_HOST_NOT,
    'affected because no Trio-based PFE modules were found');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
