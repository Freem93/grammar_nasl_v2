#TRUSTED 5aece71bdc29fcc8c17df33c1ead0e046a51420a9d379741ebe2e25f82c22af356c1d28426707fa7c108cab3f4294ecea80e4e88ebd6a3a1a808cdae7e47c27583518c847ca0dd8ce45d6f36b988b2f30bd4f1774b967b8c5cddb27d23e3ae26a13cad39596101e8afe6334c54c6959f45a573565ceb9f82dc3ccaeb5fb31c44a4a276e2dd4c8e990ad4ec8289b6bdbbae538b33392ac9061584ca890d8c8191cdd1c2966bd0a282f0d65da9eb2084b2740d5463e8eec370f2e76887787533c598e7ed844453ce53eb23ce38bb01c481366394d2d0aff12db34095459863dc497e3e077837d80fe4d965509c712de80812a986469e377b825f76e724c08888fe949a8a697b3d0f52f5d46d7abab79210ef47c23a55952392d7ba1e52036d6b18fceaee99f2047ed936f1d2d4648ef44926445390940f98299c87e1a2bce386905f9555d5c52af18bf623bc7dc26129bc0bc83a16dbc0ee8a3651a26fd70a1642f51e5827c677a3ae3683a68b1011905f7bcf041bba50d8fd6ab0699ee59dd164fa9e8684ddedcebab30c9f9149029548dc3a34260d5d5ef39addd2bea321857bfa5f7b2fc13d3a07f249c5b3358bf74b615f99ea9ccceadc01328583aec280484f726eadc47f4927b884261111a5d58b04c5ed8671360eb908f15ec3a21f881b4c5a245cb6e61d259b394c4c18c994c99c5b9a4e57420c6a69778d681e7b2573
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78423);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-6378");
  script_bugtraq_id(70363);
  script_osvdb_id(113078);
  script_xref(name:"JSA", value:"JSA10652");

  script_name(english:"Juniper Junos RSVP 'rpd' Remote DoS (JSA10652)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
improper handling of RSVP PATH messages. A remote attacker can exploit
this issue, by sending a specially crafted RSVP packet, to crash the
'rpd' process.

Note that this issue only affects devices with support for RSVP
enabled on a network interface.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10652");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10652.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/28");
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
fixes['11.4'] = '11.4R12-S4';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D30';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R9';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3']    = '12.3R7';
fixes['13.1']    = '13.1R4-S3';
fixes['13.1X49'] = '13.1X49-D55';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2']    = '13.2R5';
fixes['13.2X50'] = '13.2X50-D20';
fixes['13.2X51'] = '13.2X51-D26';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3']    = '13.3R3';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == '13.2X51-D26')
  fix = '13.2X51-D26 or 13.2X51-D30';

# RSVP must be enabled on a NIC
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols rsvp interface ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because RSVP is not enabled on a NIC');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
