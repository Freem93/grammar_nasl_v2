#TRUSTED 377808f5421dc8534860dd9439318c57b357badf6d568c73fd6d3d5660577918d8bd2eb69dfbef3a4f926b01528f1d0844592e40b94c1bef5955227b3b07113edb57ee592ab2896905d512c3a2046618521a871b402b3b13244dd0e2101f96afecddb81f25ce4a1056b29639a8bff39ebcbd9c9a78a191df9135a5f467fd438806d50aa824cd065d0f0a57d17967394ae5c33ee82bfaba69422982ab8761de271b472271d9be6475e730de92753e76b31f520d3f922f8e5183b1527451d160171703e84be7c27a73a587ce245b32bcae59435ad0df81adf7cae972a4a5ae1241d80c46a71e9393514eb6046e4ba11cbf2e080f4f1ffe5c3fcb834b135467e7d6ee56b8636d0ff981a02ddf01f98f14b2ef8a325fcbf478032873ca8117ea39e706f290c7e4ecb4e936f3dcd748d190b34d90a3c871613cb4551deb8297a01d5186ce2b4c030638ae8d5d765dc02c73d31476cc242d928280eb13e1d4d6459057810dd7022cd2e6368e2b2aeed0370f5a0b9cfa88dc4a981a995987e30a7d0d2244dd22f1d1f14eb9007f591700dfa2a4d9987b82cac35414d7d1d8dd0c6a8c567bc764a16f648b21aa3fdb9af69c574e718e6b762ff9646a059b760355597be7788896ea1afa1a50dde4a36b4884bcc5b323705fdf0dc442e1aff8a43698b9f961d7840feac6c9c2b79993c5ed91685184eaf57907c04ccc0d59a4190129ba4a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70479);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-6013");
  script_bugtraq_id(62962);
  script_osvdb_id(98369);
  script_xref(name:"JSA", value:"JSA10594");

  script_name(english:"Juniper Junos SRX Series flowd telnet Messages Remote Code Execution (JSA10594)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a remote code execution
vulnerability. A remote attacker can send specially crafted Telnet
messages to cause a buffer overflow the flow daemon (flowd).

Note that this issue only affects devices with telnet pass-through
authentication enabled on the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10594");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10594.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

if (compare_build_dates(build_date, '2013-07-11') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '11.4R7-S2')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['10.4'] = '10.4S14';
fixes['11.4'] = '11.4R8';
fixes['12.1X44'] = '12.1X44-D15';
fixes['12.1X45'] = '12.1X45-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for firewall telnet pass-through authentication
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set access firewall-authentication pass-through telnet";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT,
      'affected because Telnet pass-through authentication is not enabled'); 
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
