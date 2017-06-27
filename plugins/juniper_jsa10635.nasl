#TRUSTED 90bdb70e8faad414ac242ffe3b052e092ca939aa4705943de3ea244b232cee329c6a973b6e57a6a64d8ccecefdccdc59cc416ebc51a01d86827d681cdce5b2f6c55b2280ed6b2883f20f7b9d7c1fa2bf68874daf929ecc2da4bbbefaae75da8de6ea895c9a6e56d4133b0e92c20e5f140211b5e0aa863df18dbb064f2f69478a88d4152f95e4bbcce0ca410f271baab8d6adc6a9d798ff9fbe7e94bd88d3dacabff1c09f60cdc53a3be24975147625310d5330d95cb1048facd373bee42e9bacb02f1a947d6060134ebd40366201f9bac649293f9e7c36b682b2364cb92d755d69933416a62198e86c1de74f56070920ad16733a19b0aa2eb821600d8b0d7667a730eb6ed72018abe7ab083c288aa8f5059e755347a2e697329c0d71511ecbf7d88c00c8abd06764bc4013c1b50522b201905fba96ef78062b3cf76b0395674e0dbb9bb623d453db5edb5207801118842de0d9b71418480a194a693634142bf460f4a8564967c05efd8a9c358368ccfe35ca4fc45ce0d4a4c757a116ff879de81464d29c87e1ad08dd596614c16a8499c0a6008116da6e0f9d73db8632780da14fa10c7507d9ec534d57098e00a5e45c12e431743484206881cec711f4302b170c0e9779a31f363f4af8ec7f5bcbb03cd77eb7c16f4b21d1e6d6ea20083c51500512905ead20d81af485b54884812e90d1c97560d7b4976d1e06164e7a0337ab
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76504);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3817");
  script_bugtraq_id(68545);
  script_osvdb_id(108935);
  script_xref(name:"JSA", value:"JSA10635");

  script_name(english:"Juniper Junos SRX Series NAT IPv6 to IPv4 Remote DoS (JSA10635)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a denial of service
vulnerability. A remote attacker, by sending a specially crafted
packet to an SRX series device, can crash the 'flowd' process when the
packet is translated from IPv6 to IPv4.

Note that this issue only affects devices with NAT protocol
translation from IPv6 to IPv4 enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10635");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10635.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

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

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

# if (compare_build_dates(build_date, '2014-07-31') >= 0)
#  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

if (ver == '12.1X44-D32') audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['11.4']    = '11.4R12';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if NAT protocol translation from IPv6 to IPv4 is enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set services nat .* translation-type basic-nat-pt";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT,
      'affected because NAT protocol translation from IPv6 to IPv4 is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
