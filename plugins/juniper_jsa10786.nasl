#TRUSTED 2239e2628784f37d8063beb718bd055ee607bd95d780677a8d3d4bada4591fe5d48e95b40175cb547046a8b6a21490910bca2cb4171828d8fbc286f4d0e679acb6f7359a404fba9e6b56e4954888adc4b308f1439e4369430df00129060215dae58fbe4c659a0d3a008e7247b3306d5572dd333150881e231555f129aa4ab0104e47965143f0c1e420bcb3f87073f1741185f49631270d6eb23f115acef92f989240aa00bcdea05434bd2eab3bfd395f81f0c29df44d2ac617e3ff59722f862efdadec9d2b66147f943b5683a8f941f41d7d38956e1a5e1828b8c5a357bcb5753f778a8d180b46821e3eae485f4c4bd27e08571807445935e89b8adb72fabfe81f883a85080b1d80f8863adc972c1899ba9eb26883fac01d1297b03df81e4548e6045fcc637f2536a8c624ff6fb2da3b5c45ce007a836d47ca292f0e8288a1b3f647f51f6eaf829c6f427684cb0b70dbbc54a45db3235fbc4cdbd40ec0e821b7484bcab9591444a983e2a896bf53c091bc7bb4c8e1f5848d4156e849177b02802dded008007f95f77919db0b800fd1e79e2d84433240e85a236625059ea7b18e5f0747782c089210dbcb2f8ced729ce37bb9235c458ffe534440f284d0d4fc6929eacd08cd7e6830ceb87246cc6d91057e86f1f3c1b7206b10cd9e826013567beb3fef8f8e42f939b3d7a0f307928036c8dfa6651f865a5dfe7007c28b355777
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99527);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/20");

  script_cve_id("CVE-2017-2340");
  script_bugtraq_id(97607);
  script_osvdb_id(155437);
  script_xref(name:"JSA", value:"JSA10786");
  script_xref(name:"IAVA", value:"2017-A-0121");

  script_name(english:"Juniper Junos for M/MX Series Routers IPv6 Neighbor Discovery DoS (JSA10786)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the remote
Juniper Junos M/MX Series device is affected by a denial of service
vulnerability in a Packet Forwarding Engine (PFE) when processing IPv6
neighbor discovery (ND) packets that originate from subscribers and
are destined to M/MX series routers that are configured with Enhanced
Subscriber Management for DHCPv6 subscribers. An unauthenticated,
adjacent attacker can exploit this to cause the PFE to hang or crash.
Note that this issue only affects devices whose system configuration
contains 'subscriber-management enable force'. Furthermore, devices
with only IPv4 configured are not affected.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10786&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c1c5682");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10786.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^MX?")
  audit(AUDIT_HOST_NOT, 'an M or MX device');

# Workaround is available
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['15.1'] = '15.1R5';
fixes['16.1'] = '16.1R3';
fixes['16.2'] = '16.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration");
if (buf)
{
  if (preg(string:buf, pattern:"subscriber-management enable force", icase:TRUE, multiline:TRUE))
    override = FALSE;
  else
    audit(AUDIT_HOST_NOT, "affected because DHCPv6 subscribers is not enabled");
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
