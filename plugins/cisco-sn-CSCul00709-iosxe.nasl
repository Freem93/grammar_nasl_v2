#TRUSTED 01862207323e4812ce87b62502a586f62feaa7540ff8b70dccb2eb0b4fbaab1b4416354a14803fad7ae121ca772a5683e758983bab0ea7a9443259ac4f9d9c37a03742232aa2131b0fe2a0bb5f0bfc3049d51c51e66e898685099306003d3ae0bbb3a6c03247ac2f38a5e7f902e0a05eba2b670ae18bfab519f69b7c34ddde66599798cd2eac6d4385b48f4fb2280f9d45a6d092583e7da09097953a292ef608f18afe7baf048c95d6d8e25373a48949a5ee74e5314fead5eaa00538bfebca0c10ad2a1027f475e1bd735bf3c98a3174a4074f8a586efc5e86cdc9f4e17eeda25b350975ac0a91e307032636f5ed6f93a0d22e412fc7e08ededccfbd7556050380e9807efb8a004e0d5bc47e004b46ce10e9d5923567773dd8592c002d291854eaece9aa3325266819bc3859e754c26f59f35ef35a25e084349459028681cb4aa3db2c105fcfc572516dabeaf2753030ae808a8b7be5155ae36ff7c27c126732cd71e4b6db533c7ce38c19e47008c0e4754beab432cd79280545a52d745264794a8c3403eefa86bf6f3d57d01b29c3ee5184d55907ef318ce02b4e9daf31e455f6ae3f4598e9c400b874cc5d5ed9bf5b754880fb6fad171bf73afe3a6c302531c17317af0bb9c7329b878e7a810515ff3c84bd5c4e4d06c70392e337cdf9f9087bab13d7a04491851ffb8f54631140ac7a5fee4ccb2ea6a17c9953a1eb26c0cd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79146);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-6981");
  script_bugtraq_id(64514);
  script_osvdb_id(101423);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul00709");

  script_name(english:"Cisco IOS XE Crafted MPLS IP Fragmentation DoS (CSCul00709)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable IOS XE version.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS XE device is
affected by a denial of service vulnerability.

A denial of service flaw exists the Multiprotocol Label Switching
(MPLS) IP fragmentation function of Cisco XE. An unauthenticated,
remote attacker with a specially crafted MPLS IP packet can cause the
Cisco Packet Processor to crash.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32281");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-6981
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33e0cbd1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCul00709.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if (model !~ '^ASR 1[0-9][0-9][0-9]($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

flag = 0;
override = 0;

if (version =~ "^2\.5\.0$") flag++;
else if (version =~ "^2\.6\.[0-2]$") flag++;
else if (version =~ "^3\.1\.[0-3]S$") flag++;
else if (version =~ "^3\.2\.[0-2]S$") flag++;
else if (version =~ "^3\.3\.[0-2]S$") flag++;
else if (version =~ "^3\.4\.[0-6]S$") flag++;
else if (version =~ "^3\.5\.[0-2]S$") flag++;
else if (version =~ "^3\.6\.[0-2]S$") flag++;
else if (version =~ "^3\.7\.[0-1]S$") flag++;

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"mpls ip", string:buf)) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCul00709' +
    '\n  Installed release : ' + version +
    '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
