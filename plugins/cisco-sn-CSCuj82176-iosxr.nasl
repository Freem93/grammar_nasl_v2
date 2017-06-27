#TRUSTED a75965f01865cce60603a5674fb2965f6f9e46d05e73a0e498d8308ac4924f8c09efcf8af6b6695f1a7523290b3acfbc1091fdfd34a3efd9f30d346e42975adb895485cd6aed50a9e222f2153376791747c035887c17733c4431db9ba3ce2aa88a4ca3a1cf5c6ba1c6c871b19f3aeef294cd5333c731f260c171ad297af83de3ddc1d39c445e72fd1efa4e37ad5188f93f9756d2280ae41e45ab4400c28cf22c6f24bd972809bda2d964574a1350852dc86a2d33c23e37f560503ba5a63c2ec565a052583a9c3755cd15653a9eb2509c0e9e73393c0bb3661e02988821c00b85b8ebe438ee52204adba0f025eae6220e7aba8c3564f7851a06cf5b8d94a374d21c669ab57acef6a6fbb6f8e78d9c3ccdcb9dbb5854e57e1597ca71b0b3356762c39f8fd824fbaec010c2de9ebb360100bc9c84fe2a276553470158a1943144f0469a532a25b96e843672580952cd79ce3e54d4d8c137f5bf5a1d00ca356ae14d077d214bf7c7bcd71d2d44d8ae3247e1051979f4c9f9bacfa721cec040d14dac1e45df16132f572168c6907097baaf47b623314d70688ed903959c08123191de797c58b3d4b180528b28eda4ff294a74b0c671f57af42235900ebf54e9694acf13a8c53f29b5ecee2178bd6427fab2320859d8281d05db2960e1612bbb7fb4ec97e1449caf52d1d4fe4796a5fce4db546fba8ede7f0177c4716a8161931cb6d7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76865);
  script_version("1.3");

  script_cve_id("CVE-2013-5565");
  script_bugtraq_id(63563);
  script_osvdb_id(99520);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj82176");

  script_name(english:"Cisco IOS XR OSPFv3 DoS (CSCuj82176)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version Cisco IOS XR software
that is affected by a denial of service vulnerability.

A denial of service flaw exists with the Open Shortest Path First
version 3 implementation when handling a type 1 link-state
advertisement packet. A remote attacker, with a malformed packet,
could crash the OSPFv3 process.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31675");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5565
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdc32b73");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug ID 'CSCuj82176'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/28");

  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

flag = 0;

if (version == '5.1.0') flag++;
if (version == '5.1.1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_ospf3", "show ipv6 ospf");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"ospfv3", string:buf)) flag = 1;
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Cisco Bug ID      : CSCuj82176' +
      '\n  Installed version : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
