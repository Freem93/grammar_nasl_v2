#TRUSTED 40a664d76377eed1cc657ca358e8f1c3f62a4576bf62de3d552acdb269890d88e9aaae900e84ef823a3d1cd8b2383277135b0b3dae15d534040de4a5d21bc03d70430f3a81ff64cf903292be6f3e9397a98da7e0d027ca972ecbe089181f59a192ae36a01c6c0ec9c1de1db53baab789ead473292f285b2932ed0fd9c54ef159a8cbfa210bd5eddfd8ba636a226dfb6a5c9cad27a2a6b413d11a47d3481b9423ea98926b4d8db593384035ca16f4e2c89aa90fcbc2026d8a166c0b2a97079e1894f12907b6bc75897e2e4083e27b1f1091db9ed6ac3d05ed7b23c7bbf5d2527f656b47480e4c6a6fcb15d0136376075fb7fd16e767b6bbf7fc61cbe5d3173dc8199688d9cf0b7c6672aac0b8c918e286c59082ff1d67448dd9b9ec10a5ee5c340bba60d09b0d5ff52f389d5c8c7888d191d09ea1b8d5515500b1479f5e7eab791e7aa8a6fb2c517fd0de1d378bf8bf29d92b28e5836a793f98fa7724acedb8ab43e24ccc2b8cb337d3d6bb101a406bfb2beedda9f6933a6adf7159066fcff51521ab3d2805aa43a2735b65bd3ea975d94607b8834dc2b132c959e3307bbdf752395d130c9709e79ee5a51d8a18d8ee4aa109b8015bf1334fff171d35b4a0b5351daed1d98775876117ab9b388c449860ea697d569bb046d951da18ebc56f516b6e353083b2860c0cabb393dfa5058f389738765f11dcf76fd4a8e9a511900dee
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76502);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3815");
  script_bugtraq_id(68551);
  script_osvdb_id(108934);
  script_xref(name:"JSA", value:"JSA10633");

  script_name(english:"Juniper Junos SRX Series SIP ALG Remote DoS (JSA10633)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability. A remote attacker,
by sending a specially crafted SIP packet to an SRX series device, can
crash the 'flowd' process.

Note that this issue only affects SRX series devices when SIP ALG is
enabled. All SRX devices, except for SRX-HE devices, have SIP ALG
enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10633");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10633.");
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
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

# build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');
# if (compare_build_dates(build_date, '2014-07-31') >= 0)
#  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for SIP ALG
override = TRUE;
buf = junos_command_kb_item(cmd:"show security alg status");
if (buf)
{
  pattern = "^\s*SIP\s*:\s*Enabled";
  if (!preg(string:buf, pattern:pattern, multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the SIP ALG is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
