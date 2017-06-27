#TRUSTED 59aa9f6d9ccc37c65423b55938cd3b71ca6c3df735fcd2510dddd1bf1459b9bcb720ff7543a2463a117bf8963ad83b8dc215d463b4d6606c5152af64248916472b76f4a6985d7144202cbd69e73c718b254fe9df10b0799be52215d85ee7ea514db81b23ef4164d2def9439c1b894ee26153375b71d1239a64dd0c48d21d8629739f8c51b1a3b88cd64eabbb5cb5b6ed176a3dc2513d884382113aee976cb2f021c46072830b2f7883f28285b1d0869a309cc3e9c1d9264f06db5e43d5f24d1e7ee410a49fd7865743fe020d09cf98fc86d614c432631ee4606f03fc9d712a4f61b48417598f73a582e83d4aa97fbd8843aa440fc94c615663e90f55edd8364e0f2b6ad65cd10f5c860ee138a28e26ad6d89c04c90050005379a80c1e60db604a9cd9628c57ed1fb0fbcbc258118ed863784f452b9998b087a65bf0451028b504c0a16a6dd6c70fa655432dbc06051752d44bdef1e0435464da11d8d5af6437fb37a7129947d07e83f1ca2f963f8fd93119ead94a486ee89f34d04e1a6ed1bd40e8cb626b9e672215318cf0198b11a591ec9809acf43699763eb8caf9e9007260d5c31b82b25f50ac3ab981c2462263537c060d87c2c2dc24ce0f3e5dc15af8eeca96f33ddb252e023df47d8923eaf9099e1db54a2e8f696271ee219b71944c5ad8510f1e30063e77b98755c4a8b0d9fc263f19e76b743b51337d62623870de1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83733);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0710");
  script_bugtraq_id(74386);
  script_osvdb_id(121402);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup37676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup30335");

  script_name(english:"Cisco IOS XE Software Overlay Transport Virtualization (OTV) DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is affected by a denial of service
vulnerability due to improper processing of oversized Overlay
Transport Virtualization (OTV) frames. An unauthenticated, adjacent
attacker can exploit this, by sending a large number of oversized OTV
frames requiring fragmentation and reassembly, to cause the device to
reload, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38549");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCup30335 and CSCup37676.

As a workaround, limit oversize packets across OTV topology.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check model
model = get_kb_item("Host/Cisco/IOS-XE/Model");
if (('ASR1k' >< model || model =~ '^ASR 10[0-9][0-9]($|[^0-9])'))
  audit();

# 15.3(3)S1 maps to 3.10.0 / 3.10.1S
if (
  version == "3.10.0" ||
  version == "3.10.1S"
) flag++;

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_otv", "show otv");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^Overlay Interface Overlay", string:buf)) flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup37676 / CSCup30335' +
      '\n  Installed release : ' + version +
      '\n  Fixed release     : See solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
