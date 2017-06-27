#TRUSTED 5221a5225fbb9c75612fb8674f8e4cf592b7879ab6d3c4f55b3e8248189a4137291dcc1b40ff2a4b129ce56bd505633fc3df993223470cca21f6bd4ebbcf5a25a8479027905c61300215b3064204987f8642a4c3be76d0f290c55ae5924eb13f60ec45974a9b1006f93c4dc0749c2dc932e2c70b8ac0bef70422408118f89275242c1f1dba545708c5b889c3498c318c0550a364fcd53cc0ce7a440f6cffba6bd41b9f325809c3ee4164c7234de248e393d24afbf4eee105bb60cee556b3272bd23bbd8734e77dea5b3be723fda7ba5650bf5bf39fd8dbd73bc695bf3d7d8b198393920f964f78e725245cf123311faf3d17fb928a89344af83ea67fc64c1e0d6d6cbabd90078e19b6aaa670fa0f7484837d63fe5dc7f4d7a9826df95afc3508fd9f4f32c94b240d1c0e02470b9a7fa71cc7b6daf2b8d927dfd2b9d9c36d38ca77577ff2a24a2bf44a02401e76ff28e86907ca081de3dbe5b43748322d60b8469f3869e55c825153904acc67c7b614ae767eb160e82db8c164cb1bc66431f04d61bf917e19e7fb63226118390120011c07321dc71a7e513069f6f14e4791196bdfba2d17f5f5ecf2b970c321504144a01e884add14eb4c92f2699620e59989216b2eedbcaba797df0725b332122f02f74902a8a1f1f52836095fbb1eee30aa6c168239e9f967ec0d39271552464af5057bb25610e9e2aecddaae2cd2eebc0fd8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73495);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2713");
  script_bugtraq_id(66764);
  script_osvdb_id(105614);
  script_xref(name:"JSA", value:"JSA10621");

  script_name(english:"Juniper Junos MX and T4000 Series MPC Reboot DoS (JSA10621)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability. The issue exists in
MX and T4000 series routers that use either Trio-based or Cassis-based
PFE modules. An attacker can exploit this vulnerability by sending a
crafted IP packet to cause the MPC to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10621");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10621.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

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

if (model !~ "(^MX[0-9]|^MX-MPC[1-4]|^CHAS-MX|^MPC[4-]|^T4000-FPC5)")
  audit(AUDIT_HOST_NOT,
    'an MX Series or T4000 router that supports Trio or Cassis-based PFEs');

if (compare_build_dates(build_date, '2014-03-20') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '12.3R4-S3')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['11.4'] = '11.4R11';
fixes['12.1'] = '12.1R9';
fixes['12.2'] = '12.2R7';
fixes['12.3'] = '12.3R5';
fixes['13.1'] = '13.1R4';
fixes['13.2'] = '13.2R2';
fixes['13.3'] = '13.3R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show chassis hardware");
if (buf)
{
  # PFE modules part numbers
  # https://kb.juniper.net/InfoCenter/index?page=content&id=KB25385
  part_numbers = make_list(
    # Trio-based PFE modules
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
    "711-038634",
    # Cassis-based PFE modules
    "750-045173",
    "750-045372",
    "750-037358",
    "750-037355",
    "750-054564",
    "750-046005",
    "750-045715",
    "750-054563",
    "750-044130"
  );

  foreach part_number (part_numbers)
  {
    if (part_number >< buf)
    {
      override = FALSE;
      break;
    }
  }
  if (override) audit(AUDIT_HOST_NOT, 'affected because no Trio-based or Cassis-based
PFE modules were detected');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
