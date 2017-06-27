#TRUSTED 8b6851aae7a0e9031b3cfbe2ea90e9717b36af2a3ed7871b3303d4de97542d813ba4bcce46d00c1960b40e6b45b939c2963808fc872530ff7b51b2432b069c6c13ad51f4ee29eb85db0344dd1e1d75c4c1625fd9d9779fe3299cbd47c307aa9f1575e6545fbec4af28a0da85b73b59a2e164cee77277649300b0aed18e21856cba5f5f318cf52a865ab77527f3f811d87d7a6df05d49d8e84f25fd2bfa2c9bc25ca036ec90863d39ce2b8ccfc8394971ea53bfe31163ae3a6da2bae6828cd4eb73e2127203194d14bddd89de6b983676d277fccf910fc727d930d3c67c75d1e2ed62293cf7bcda1ca7acff139d2ceabcd422666488cd25de5a5b8f1377daa3270ca5bb81fc80b64c08fc57d7a0a1509fe12be4603a1d3477086c6f0c5f57503db4feca98b907b0f8ea9b11c8f8528a82fd75d2e777f9f4c33200edb22b9429e6ef143c221fde0a769d0005f93ea6e7e25cbe1e625c38e45c70792153b4af1587cb66d127f8031d6a85872511ddd48d4ab378709151b79073be86e4d9bfde3c072f6ce724f195de450141eab03fa3cd7b6d9f2726701a7691816db2ef5c60491805149979c7eef1bee8bfc07b30225ee7b7d7c9fa8eb4bdec3832ed929582b387906dc88be948996c7a68189f15fa118dd718d7a55427d760588581c8ebe3c6fee4c45ad51c59e655619f46b8ad38b5d83f83a9f4546cbcd28218ddd325b73627
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78426);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/05");

  script_cve_id("CVE-2014-6380");
  script_bugtraq_id(70369);
  script_osvdb_id(113079);
  script_xref(name:"JSA", value:"JSA10655");

  script_name(english:"Juniper Junos 'em' Interface Fragmentation Remote DoS (JSA10655)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. A
remote attacker can exploit this issue by sending a set of specially
crafted fragmented packets to cause the 'em' driver to become
permanently blocked when trying to formulate a reply.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10655");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10655.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
  flags:EX_SERIES | M_SERIES | MX_SERIES | PTX_SERIES | QFX_SERIES | SRX_SERIES | T_SERIES,   exit_on_fail:TRUE
);

if (model =~ '^SRX[0-9]+' && model !~ '^SRX5[468]00($|[^0-9])')
  audit(AUDIT_HOST_NOT, "SRX5400/5600/5800");

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1']    = '12.1R9';
fixes['12.1X44'] = '12.1X44-D30';
fixes['12.1X45'] = '12.1X45-D20';
fixes['12.1X46'] = '12.1X46-D15';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R8';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3R6']  = '12.3R6';
fixes['13.1']    = '13.1R4';
fixes['13.1X49'] = '13.1X49-D55';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2']    = '13.2R4';
fixes['13.2X50'] = '13.2X50-D20';
fixes['13.2X51'] = '13.2X51-D15';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3']    = '13.3R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for CLNS routing and ESIS
override = TRUE;

buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set routing-instances \S+ protocols esis",
    "^set routing-instances \S+ protocols isis clns-routing"
  );
  foreach pattern (patterns)
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;

  if (override) audit(AUDIT_HOST_NOT,
    'affected because neither CLNS routing or ESIS are enabled');

  # 'em' interfaces are the only affected interfaces
  buf = junos_command_kb_item(cmd:"show interfaces");
  if (buf)
  {
    pattern = "^Physical interface:\s+em[0-9]+, Enabled, Physical link is Up";
    if (!preg(string:buf, pattern:pattern, icase:TRUE, multiline:TRUE))
      audit(AUDIT_HOST_NOT, 'affected because no em interfaces were detected');
    override = FALSE;
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
