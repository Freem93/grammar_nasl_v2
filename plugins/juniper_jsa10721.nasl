#TRUSTED 0dfc268ecfeb70d59593c1fa4ce213baa321a935dcd1818f280e6573b7a1510148f587635431a2e0768ef5b6998b49fb9f087022bd65fe8cdc0af4b30e9181b44887da747af2c45497cef18aa5c26e226720f44815f311e0376a39cf6472440cd3efd41b7fa026b3164a946c79b3420dcba369578fa948c2153c7ababf3289595d5540ec67143f22e7f69a7c7e50b00eedea43fbea63567e465dc54ee487d0058e4b8270245cc5900deddecd34a356aa19164996b5f26b5e1d2e98ee067d23fdd75e16be872cc83c4d0db9512118f70985d6c6ffee7aa1e225a691f35ef73346ab93be9929916eb9c21d3f153dd3e45a0dbba4326f1f898a6140ec2221f4c663dc194c6d6ee1d94ef59bae3cf2ea1365285e05beb6902e91f31625f4b088fba8f08361f9ca14a7d916850d673b83f30a87bf52ed5056af58414055d12d5f8ff55e4de06684b89acdcb43eafd951d98445548f49031c678ec2ea56480e09b64e2e4b85b4be67b450b0e9be4a6ff0308bc211cf2b2e502c83aa7f9da7b58aa55b2b5433919bc1a992b0e894c32fe4ae8250afa726c0f4c6274908fcef44722e85d318760a278456efa4049c9d12dfdc9c77a491f4533e877e8690ac6459977e4c4af23ab034e6dfe5c93559fdf77950ea11bde81b698021f883d6647fd6a29918c79138e9e0ccd28859b6921d45df5f3ebc2d4d58acd3fe25a73543dbc6cfd9980
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88096);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2016-1262");
  script_osvdb_id(132865);
  script_xref(name:"JSA", value:"JSA10721");

  script_name(english:"Juniper Junos RTSP Packet Handling flowd DoS (JSA10721)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by denial of service vulnerability due to a
flaw in the Real Time Streaming Protocol Application Layer Gateway
(RTSP ALG) implementation. An unauthenticated, remote attacker can
exploit this, via a crafted RTSP packet, to crash the flowd daemon.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10721");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10721.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D45';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3X48'] = '12.3X48-D20';
fixes['15.1X49'] = '15.1X49-D30';

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show security alg status");
if (buf)
{
  pattern = "^\s*RTSP\s*:\s*Enabled";
  if (!preg(string:buf, pattern:pattern, multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the RTSP ALG is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
