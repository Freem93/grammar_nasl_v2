#TRUSTED 7536c54b1c841f2fd819beea6582b46f535f5780f4aae1124ea9c0c5fd45e734000df298c26bb3872bd987433fe9e87894bb97d823f430427033b30700c8527b7c9948a7b8fac2d33e8d67c7d4c18bc6b546135d155c67211ce85a7f31152b9fd491e04b0c2db8032dd50d13c940809762ab6b00edab9b505614bd99695d91b7d865edd51db3d4ec91e7e6381e1a7985c4cc4635b3b7c6f317666ecff304509de1870bee1820216b33ea931ea7bee787fdc3f49b13d05e4da86f70034f65d19052cc085ea42ec9191354db6ec434e8c54ad518bb3bcc2cb20a869deeb9dea5a2e31055c90b1ceac4848764b127d5b1fb47dc2a102a7fec750a6f27d6cb911c7c0e099aa95ef1101eee80bda99b8f7300068d1adc5d26854b0a18bcad8d1d829fc69eb6818d67baf9b2062c9a96b83c9dee1e3a3755cd2e13243daaf7c754a9ac383f6a4cbb35d1e560f860de9fc1e92c90d224579ee19d419b0a66a3ba30d1f3b0a5ed27c11eb6ca7d8d68ba6621358baa5372dc123dbc02d0803577d977afd8882cad3c46927b99c8e58c2b3a561fe5076bc6f315979364be62efc5205cba78a989ac19561a7a69db1b7c06ec74c15a4a01cf399022cb1137acbc6316093b7f2461413d3d05c57944e785ba558febd1094d8b0b751ddf47e539b2dc81ee680c97e9d15706865436918e2f5850c11092350dd841c30e6a638cf8e944f9a583ff
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80953);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-6382");
  script_bugtraq_id(72070);
  script_osvdb_id(117040);
  script_xref(name:"JSA", value:"JSA10665");

  script_name(english:"Juniper Junos MX Series BBE Routers jpppd Remote DoS (JSA10665)");
  script_summary(english:"Checks Junos the version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability in the
Juniper PPP daemon (jpppd). A remote attacker can exploit this issue
by sending a specially crafted PAP Authenticate-Request after
successful negotiation of the PPPoE Discovery and LCP phase, resulting
in the PPP daemon crashing.

Note that this issue only affects MX series routers deployed as a
broadband edge (BBE) router.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10665");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10665.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

# Only versions 13.3R3 and later are affected
if (ver =~ "^13\.3R[0-2]($|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, "Junos", ver);

fixes = make_array();
fixes['13.3']    = '13.3R6';
fixes['14.1']    = '14.1R4';
fixes['14.1X50'] = '14.1X50-D70';
fixes['14.2']    = '14.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for PAP authentication 
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set interfaces \S+ unit \S+ ppp-options pap ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because PAP authentication is not enabled');

  # Check for the Broadband Edge (BBE) subscriber management daemon
  buf = junos_command_kb_item(cmd:"show system processes");
  if (buf)
  {
    if (!preg(string:buf, pattern:"bbe-smgd", multiline:TRUE))
      audit(AUDIT_HOST_NOT,'affected because the Broadband Edge (BBE) subscriber management daemon is not enabled');
    override = FALSE;
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
