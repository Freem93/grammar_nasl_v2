#TRUSTED 47fc298d5759676a6bb535619efd3fc7d171633d4e07ec4480f54837984690125c78b00441d53b5f7e81722e8e9b441b869b95c7c891fc358805752cca5b852fb5ce5325d477f98623a3a71ddd5facf7dd7082e8c6405602e0546b6f61dcdb90da5a24546389e5629019c287f8cb6b2c4c459fbff24484e11ab3d5a04d23c9fc0b508bffca202cc7995da619b042cc549f5764401e1b6b903df0f8992a55310b957cd0f815eb9a40d783797e1aa699ce49fb56c0ad4d3db42b0af30a633ec2124b8313809832d1881a929d84051642a2e721dcdff79b32380e90f68fee1ca55307a83dab9fde7aa1ebd8952fbb98dbcf93919d03e633dbc537f856746496bf642e27c3c9eb834c8495e80d509d9fed5422018731441f59060bdb5d3be0208c54c934ae76a36ca998c013b148b8def52399c905a4f8713a5c8c7b470371187a35ad0fb7f7998f5b1e3dea76169390ff11f803c00b164b4e44a8c3b7fe7b3523e5d862460d4208eff2560473446504a0bff31fb66a72ab16212354fcdc1fcb2a9e85f733a357383b8f1cfcbfdc87e71f71fa30e61d38a4fdf37bd24077428f85565ea092498e304398f9f2ebbe6cea92ca427b37e7a2b6ad120159ef6659cbf3a9bb54752865ba58f105f7dbe16f6becd57a51587fd626b4297fc0eaefc3abd2cc7b20563559f27af2864d0440c5f53bb87101d472ad7dc802682842a5da6b19f2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91426);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/06/01");

  script_cve_id("CVE-2015-4595");
  script_osvdb_id(137400);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu93339");

  script_name(english:"Cisco ASA Cavium SDK TLS Incorrect Padding Acceptance Plaintext Disclosure (CSCuu93339)");
  script_summary(english:"Checks the ASA version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch. It is, therefore, affected by a flaw
in the TLS 1.x implementation in the Cavium SDK due to a failure to
check the first byte of the padding bytes. A man-in-the-middle
attacker can exploit this, by sending specially crafted requests to
the server, to induce requests that allow determining the plaintext
chunks of data. This vulnerability is a variant of the POODLE attack.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuu93339");
  # https://vivaldi.net/en-US/userblogs/entry/there-are-more-poodles-in-the-forest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f38496c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in bug ID CSCuu93339, or contact
the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model != "5506-X" && model != "5508-X" && model != "5516-X")
  audit(AUDIT_HOST_NOT, 'a Cisco ASA 5506-X / 5508-X / 5516-X');

fix = NULL;
flag = 0;
override = 0;
cbi = "CSCuu93339";

# 9.3 <= 9.3(3.2)
if (
  ver =~ "^9\.3\([0-2](\.[0-9]+)?\)$" ||
  ver =~ "^9\.3\(3(\.[0-2])?\)$"
)
  fix = "Upgrade to 9.4(2) or later or refer to the vendor.";
# 9.4
else if (ver =~ "^9\.4\([01][^0-9]" && check_asa_release(version:ver, patched:"9.4(1.4)"))
  fix = "9.4(1.4) / 9.4(2)";
# 9.5
else if (ver =~ "^9\.5[^0-9]" && check_asa_release(version:ver, patched:"9.5(1)"))
  fix = "9.5(1)";

if (isnull(fix))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA", ver);

if (get_kb_item("Host/local_checks_enabled"))
{
  # Check for the workaround
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_all_ssl", "show run all ssl");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^ssl server-version tlsv1", string:buf)) flag++;
    if (preg(multiline:TRUE, pattern:"^ssl client-version tlsv1-only", string:buf)) flag++;
  }
  else if (cisco_needs_enable(buf)) {flag = 1; override = 1;}
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_note(port:0, extra:report+cisco_caveat(override));
  }
  else security_note(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
