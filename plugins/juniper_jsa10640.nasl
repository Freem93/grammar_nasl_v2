#TRUSTED 925dd8b51c66870ecad0c2737218743878d9e942796cfc75bc44ef429ba0c46f02a02a7d10e069cb067b2db5d79f97fc3a16bd41d3c975a94c687fe4a3478e8e6aa82f51af49c88e7e0a29acbf1be6765f30dd3298c7b7aaa4141e7ed9695fafd4bb009ef405dcd57f20f0da7bcacae11bff0fabaa952525e75f33b4f52671b3671304fad84d554359b49e94eb4cb015e945bd7f5262d06307f58c15b99ed32f835f55c802d546e5a06d52863e39cdb5ae438dfc35574e2a2060be834e6d3fa09df3795d570804e008b27faea5ebf98ae53f28b7ccc3985e1371195f7e8ff38494d99a7016e82ddaa3c813dfe9f715fba0bb1d45c48de5e75aa80e4f7c6df0776e28eb44bf3698ad885cd5e25023ac9a7d388e6eb7069c50c41acfe3966a82a70f2faff2d91c1e027fa6b57bc7ecbc2aeb1324c92f5730c2761dfbe50ac1821302e8fd3b4ce0df52859b4fbf75e324ddeec5b86b82aee2e7cc2cf0b56989e8a8c03744b8850893c88322bd80e4d41be09d31f126c0b90b5540fce0f2c5f2409b6b6aadf48bcbf5ff64b59a9ccdd53d69a302f2c315c018542e927aca30ef4c95642d68d78f220d14b5dd6e242493b39f0f1b224b00a1577e0c2b11d00dbbfc5b0b07470fb08272c23cd36e05d4e721d119bad62e736a856fc37059324c2bda2a8001c33e02e9fe0804a7b2fda38dce94308e58afaa38e596e07544c4824027e4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76507);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3821");
  script_bugtraq_id(68548);
  script_osvdb_id(108940);
  script_xref(name:"JSA", value:"JSA10640");

  script_name(english:"Juniper Junos SRX Series Web Authentication XSS (JSA10640)");
  script_summary(english:"Checks the version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a reflected cross site scripting vulnerability. An
attacker can exploit this to steal sensitive information or session
credentials from firewall users.

Note that this issue only affects devices where Web Authentication is
used for firewall user authentication");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10640");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10640.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

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

if (ver == '12.1X44-D34') audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Web Authentication is used for firewall user authentication
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set interfaces \S+ unit \S+ family \S+ address \S+ web-authentication http",
    "^set access firewall-authentication web-authentication"
  );

  foreach pattern (patterns)
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;

  if (override) audit(AUDIT_HOST_NOT,
    'affected because Web Authentication is not used for firewall user authentication');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING, xss:TRUE);
