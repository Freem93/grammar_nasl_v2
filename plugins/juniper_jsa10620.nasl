#TRUSTED 88e77b2b4a95e204e03840de97c42affb98a065ae145a58f5269bc7fcbff9e88ff3446630b53031f70a1501dc2c317dcfc273fb6e42a7b321850be6beb67a181d2a403d0ffd0d9174d15174ad81cc404d76dbf5f338f8c1718a36332bf8fb7de3614404b4bbf6d10385096f53af46afabf9faf3fc90463733b0cbc15c380df5d24eef8846fd29e90342d3f140f6afc7b8cf0fa25d4265a29081dcd3305a6102e5f2772730fead042975cc447333d1ce2058a693e72364aa9809d1139824acff08ecdf036d1940e870b692d9c5d65124e912c389b17a66c18548fab39ee7eaca1b17f563301dbb31a728b90351ba9f6a1c25ae15d110eb5583f4d5ea5955c78554f18b9462760a9a2fb262790cf3ef45cea2d287f892159dc91550d6fde120aa14d89e66c761f79b6b3e63d3bcdafa1401ea301b7f2f0d306ea1ed50e84444e5144f7cd98e89fe96249c923780aff052819fa867a6a94e6243935d5a8d926113db0b399a68c1d814c70aa3aaf6d0d153493ec1322999cc56bbead9588a26f065c1da5327f9ab912b46d642d1bc1fdcb9b0db80d13018066d490ef1630fa778bd9d3a7f71df5b7303ca6160fd9707ab2e45bbcfb16469601ab2209d027e80155bed7a97b886cc38e5946be04767b24c431440619f661c1da5477f62d327206193e0ba09fe8ebc71be75e740918c2a99b3387656a7e2baa438666f30dd5e85cb61a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73494);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-0612");
  script_bugtraq_id(66759);
  script_osvdb_id(105613);
  script_xref(name:"JSA", value:"JSA10620");

  script_name(english:"Juniper Junos SRX Series Dynamic IPsec VPN DoS (JSA10620)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability related
to the Dynamic IPsec VPN service. A remote, unauthenticated attacker
can exploit this vulnerability to cause new Dynamic VPN connections to
fail for other users or cause high CPU consumption.

Note that this issue only affects SRX series devices with Dynamic
IPsec VPN enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10620");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10620.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/19");
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
include("junos.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (
  model != 'SRX100' &&
  model != 'SRX110' &&
  model != 'SRX210' &&
  model != 'SRX220' &&
  model != 'SRX240' &&
  model != 'SRX550' &&
  model != 'SRX650'
) audit(AUDIT_HOST_NOT, 'a SRX Series for a branch device');

if (compare_build_dates(build_date, '2014-02-19') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '11.4R10-S1' || ver == '12.1X44-D26')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1X44'] = '12.1X44-D30';
fixes['12.1X45'] = '12.1X45-D20';
fixes['12.1X46'] = '12.1X46-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Dynamic IPsec VPN must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Grab the dynamic VPNs
  lines = split(buf, sep:'\n', keep:FALSE);
  pattern = "^\s*set security \S+ gateway \S+ dynamic ";
  gateways = make_list();

  foreach line (lines)
  {
    matches = pregmatch(string:line, pattern:pattern);
    if (!isnull(matches[1]))
      gateways = make_list(gateways, matches[1]);
  }

  if (empty(gateways)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
  
  # Check if IPsec is enabled for at least one dynamic VPN
  foreach gateway (list_uniq(gateways))
  {
    pattern = "^\s*set security ipsec vpn \S+ \S+ \S+ " + gateway;
    if (preg(string:buf, pattern:pattern, multiline:TRUE))
      override = FALSE;
  }
  if (override) audit(AUDIT_HOST_NOT, 'affected because Dynamic IPsec VPN is not enabled');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
