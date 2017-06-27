#TRUSTED 6fed2c3173c55a2a651946aeed3de97af549d4f1b001b892a255f263226d06a79e07414bc11e506c7c0182de442ab9d6123d868bc47d071df769293a7a67b180b42acba924343f8fa5ab7ec04bc324852bf51d4302c659d5b57f8350824d26b3078c4c04f2d4e483c5a80477e380cb8d455e47c33444be5d46cb6dc1f8ee084431ce39fdf67ffe57625a1793567b1e27b75a6425be3916eb8c73d739107a552d068668a61d239e271bb3b2fa806ef7fb0d314d1e74a7b7e381f20810bd89ef9d32254c1c236500d63d3061bfd723c78104f26f3b511c989ad2c6e75711396745aafea0c298eec69a027f85640f1e1db85e415de4c8d5dafb57a9e4174e61bfac4e2ca312924b0a48637cafa01169837e47aeb59c28d1efc9a1ff25ce6bc08f077271d04ec04017292c24325a64ff3d7766809d1a523382ecad789dcf588254408edcbc94b3fe19fec1e63703115991a33bbeceb512c9ec4b2fafd6b156d4395ad8347af71eccefb8229434e681a4410e0abf57a1da89024ff17bdea7f36b5d28ab313f41e04af09cb70bbb29859e1d038cca6183d228927859384d8518491af29a0d445f4fc4e3f16826ce7d874841803eaa52d1528018fc6487522702df56b7bf46c8ec623f56e279e9d8d419c8151954255cc234a1f8035bfaedb136d54f992c002c51a0bcc0e779b92af24e171973617d5156280ba23bd33edeca71a15f2c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76790);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3284");
  script_bugtraq_id(67603);
  script_osvdb_id(107363);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo55180");

  script_name(english:"Cisco IOS XE PPPoE Packet DoS (CSCuo55180)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability.

The issue is due to improper processing of malformed PPPoE packets. A
remote attacker, with a specially crafted PPPoE packet, could cause
the device to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34346");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3284
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?168c285b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuo55180.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");


version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model = '';

if (get_kb_item("Host/local_checks_enabled"))
{
  # this advisory only addresses CISCO ASR 1000 series
  buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
  if (buf)
  {
    match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
    if (!isnull(match)) model = match[1];
  }
}
if (model !~ '^10[0-9][0-9]') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

flag = 0;

if (version == '3.7.0S') flag++;
if (version == '3.7.1S') flag++;
if (version == '3.7.2S') flag++;

# Check to see if PPPoE is actually enabled on the host
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ( (preg(multiline:TRUE, pattern:"pppoe enable", string:buf)) && (preg(multiline:TRUE, pattern:"ipv6 address", string:buf)) ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuo55180' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
