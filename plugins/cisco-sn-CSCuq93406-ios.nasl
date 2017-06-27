#TRUSTED 00e335a767ec770a01a81e75040b089421c6f2b69e2a16fb94deb2fd4d7be8a7c56ff20d3446988751036a30f97d08a240a7617c676698942aa1f1520dc07716b4b3c8eeb0b524d0aef3a0c8a4210cff437e59237e10ee17ba171374bd6f73b36853be57a28225e74fd4b15e1a23804a4c7c4dabe8380798149b245df3938f26a7c32c2fe85300517c5d6d3893c76da03d411faf8cc587f7c2b1b9c80eb16f80bd0293fa967477a58154639a5fd203c192d87a763df268301962f1ff59ad2b5f76e3b2e77f6fd6a9c33feb542ef1176af11c85074f379e7ce825fa23911c6a9f9c8b8a9ec02fcd3b103bda46109de05e6bb09e8ceacb97e46a7648ea68f042f7c7b91cceed875f5bf0f34ce6fea29c9c4ba315e178bd786db8d508c8710aec0087307c04001f24fdd00a722fa252c4bac0e0ba53de27abfe92981d1c9e3f0fd601e3b5c1aa84252221a5da431adb7f98e9517724e4de75050c6d862331bdf2ed72deb3510fb94e4328c1383d5146075330a8a0178d4c4ff356e0a8c36ef0d917e43824584b637221c0a3dd31385f03f434897ebab4f95a670fad144758f24915750cfa7dd66a9dad6def4e1ccc49295bc265e41bdc5c487a0c6d80601d43d1564558c6f990ef2fb2fb0c1777bfa818f20966ed5bfc59c3e29fc5e67e32eed515aa0e0a136544c37cec39c3231f863c8374152cb981d7c1182f7d8ea22bacb890
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78918);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/11/07");

  script_cve_id("CVE-2014-3409");
  script_bugtraq_id(70715);
  script_osvdb_id(113705);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq93406");

  script_name(english:"Cisco IOS Software Ethernet Connectivity Fault Management (CFM) DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is affected by a denial of service
vulnerability due to due to improper parsing of malformed Ethernet
Connectivity Fault Management (CFM) packets. A remote, unauthenticated
attacker, using specially crafted CFM packets, could trigger a denial
of service condition, resulting in a reload of the device.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3409
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa61ade4");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Notice.

Alternatively, disable Ethernet Connectivity Fault Management (CFM).");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");


  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Check model
model = get_kb_item("CISCO/model");
if (!model) model = get_kb_item("Host/Cisco/IOS/Model");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (!model)
{
  if (version == "15.1(3)S2") flag++;
}
else
{
  # 7600: 12.2(33)SRE onwards
  if (model =~ "^7600($|[^0-9])" && version =~ "^12\.2\(33\)SRE($|\d+[a-z]*$)") flag++;
  # ISR-G2: 15.1(1)T onwards
  else if (model =~ "^ISR-G2($|[^0-9])" && version =~ "^15\.1\(1\)T($|\d+[a-z]*$)") flag++;
  # ME2400: 12.2(25)SE onwards
  else if (model =~ "^ME2400($|[^0-9])" && version =~ "^12\.2\(25\)SE($|\d+[a-z]*$)") flag++;
  # ME3600: 12.2(52)EY onwards
  else if (model =~ "^ME3600($|[^0-9])" && version =~ "^12\.2\(52\)EY($|\d+[a-z]*$)") flag++;
  # Cat4k: 15.0(2)SG onwards
  else if (tolower(model) =~ "^cat4k($|[^0-9])" && version =~ "^15\.0\(2\)SG($|\d+[a-z]*$)") flag++;
  # Cat6k: 12.2(33)SXI2 onwards (note the '2' at the end)
  else if (tolower(model) =~ "^cat6k($|[^0-9])" && version =~ "^12\.2\(33\)SXI([2-9]|[1-9][0-9])($|[^0-9])") flag++;
}

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"ethernet cfm", string:buf)) flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuq93406' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
