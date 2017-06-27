#TRUSTED 6edba73cc704c8704a33f2379c4657ceace7dc7093ec92a67ddfecff263434bcb17cd02f4fa807f812e780789968d5258207a414d78aedac90496ebf8b1ff5fa473a8a132de3af62ba269f521e4914d5cbe06d30529cb50ecced7ece3e37ede33ded87c3c54cfe9898efbf379a7c79409e4dbf7be34b7e676122944bf6784d50a68794d2c7484ff36208c9bc54dc47d3c4ce320e415854fe95feacbb64fa20295c0e6f082f8ce5a4ab30d441fde8d0809b504e026fb7e5c1043162fd3886f65e41ee4ff2119d1382cfcece5d4dbaa19b4394592840886e8c5e5191044df960a391d266957418e85a871f0ee8e3c4af88ff560a7ed5114900c49dfa2c5278dd77b1858949a84caedc1c64ae71c96e90c4dc76143f2312100bcb3907ad130d8741719671eaf0773e38289ca5d91a7ba00b8ba472bd252f9724482f62497f9abbae4d746c9f991165d8c3b52d0f54c523ef1caf1ee58045f9b1d4f96d2465dd86bbd7a9cb781849031536379a30d321ec46781f203e3056d3d9be6cc6a672f80ff64ee43f9e50e0088155da951ba18d869e980954f3e0254e640549ecba49e9db6f2e308f2a2c607a958e4d8d1d8f1688430619cc0553242e8fc606cae1347910dd8b74526e6389dcdf187cbc50e1328dc5a46a97f30f1fbeb465f2097cb449be2cfb3009b86f9c81e7489c440f6cdc7ba0d016cca837690cb2d2327228aabf3e9b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78919);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/11/07");

  script_cve_id("CVE-2014-3409");
  script_bugtraq_id(70715);
  script_osvdb_id(113705);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq93406");

  script_name(english:"Cisco IOS XE Software Connectivity Fault Management (CFM) DoS");
  script_summary(english:"Checks the IOS XE version.");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

if (!model)
{
  # If no model, just do ver checks per Alert page
  # 3.1S .0, .1, .2, .3
  if (version =~ "^3\.1\.[0-3]S$") flag++;
  # 3.2S .0, .1, .2
  else if (version =~ "^3\.2\.[0-2]S$") flag++;
  # 3.3S .0, .1, .2
  else if (version =~ "^3\.3\.[0-2]S$") flag++;
  # 3.4S .0, .1, .2, .3, .4, .5, .6
  else if (version =~ "^3\.4\.[0-6]S$") flag++;
  # 3.5S Base, .0, .1, .2
  # 3.6S Base, .0, .1, .2
  # 3.7S Base, .0, .1, .2, .3, .4, .5, .6
  else if (version =~ "^3\.[5-7]S$") flag++;
  else if (version =~ "^3\.[5-7]\.[0-2]S$") flag++;
  else if (version =~ "^3\.7\.[4-6]S$") flag++;
  # 3.9S .0, .1, .2
  else if (version =~ "^3\.9\.[0-2]S$") flag++;
  # 3.10S .0, .0a, .1, .2, .3, .4
  else if (version =~ "^3\.10\.(0a|[0-4])S$") flag++;
  # 3.11S .1, .2
  else if (version =~ "^3\.11\.[0-2]S$") flag++;
  # 3.12S .0
  else if (version == '3.12.0S') flag++;
  # 3.13S .0
  else if (version == '3.13.0S') flag++;
}
else
{
  # If model is present, do ver check per model per Bug page note
  if ('ASR901' >< model && version =~ "^3\.3\.") flag++;
  else if ('ASR903' >< model && version =~ "^3\.5\.") flag++;
  else if ('ASR920' >< model && version =~ "^3\.13\.") flag++;
  else if (('ASR1k' >< model || model =~ '^ASR 10[0-9][0-9]($|[^0-9])') && version =~ "^3\.2\.") flag++;
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
