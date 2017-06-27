#TRUSTED 20581fa6bb98b21a3b254db739895ba8bf405eb78e3ebf35a6ffd81594a9d2f9c0b12f933b0ec247ec9e0d587a296dce9e398b4bf28c26123ab9caf3148ef991f2035127a2c4ab721456103ca9134183f1ee454bb4e5f9dcdb7805ad7ba980db00c8eaa2af40ab1bc969835aba23568a666d33802d44ec79c3c176f03b20f625bf2ef5560f8fa6d9701d6c7547afca9fa8972984d12451c2e5670f44aaa9a6ab36d35e5fac134f1e7d4dd9d67ebb7824e29b7f76827390332ca6d9d91298202caa34fd5b95dcf607c6968a38b5f0dcdf58f0ce4a974f6c89157c76f6364485f4d3f671534d400895bd93bb2cade1cd9f33871d72611c18789516201350b770ee9251311270aad5e23d07c4e8930fdf215979feca1c9cca0dd30cce598c4d6c52c6ed2763bf3d33a01883ab039d07fb654acc3b1b1b331a26e501d4bd930d5811c7dcb2f50724facf1c9a92a130456034589c83c65744eabd78cb2433b5455f4c9dd58dbb2fcb2f2ea2e83f9a4abb2b576a24835fc3c0eceb3dbca1f9ef85a87786162b1f583cd6d0509c22e95241e65d79032fef4769c6c726bd01dfe640d26c26ed70e67f66199aa4d0d5f0b9caa97d1d25fb5471f9c3c603d8421268cb87d86408add2b4a12cf5e96d04307f098ad39395d3d9e5b96f524718b2ad153963ed66a0c6eec1308673ccc33f393dd40addebdef08a8f6bb9a6e8aa13ebd0eeb002
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78032);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3355", "CVE-2014-3356");
  script_bugtraq_id(70130, 70135);
  script_osvdb_id(112038, 112039);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue22753");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug75942");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-metadata");

  script_name(english:"Cisco IOS XE Software Multiple IPv6 Metadata Flow Vulnerabilities (cisco-sa-20140924-metadata)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by two vulnerabilities in the
IPv6 metadata flow feature due to improper handling of RSVP packets. A
remote attacker can exploit this issue by sending specially crafted
RSVP flows to cause the device to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-metadata
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5eeb7284");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35622");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35623");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCue22753");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCug75942");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-metadata.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCue22753 and CSCug75942";
fixed_ver = NULL;


if (
  ver =~ "^3\.6\.[0-2]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.(8|10)\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$"
)
  fixed_ver = "3.10.4S";

else if (ver == "3.3.0XO")
{
  cbi = "CSCug75942";
  fixed_ver = "3.3.1XO";
}

else if (ver == "3.7.5S")
{
  cbi = "CSCue22753";
  fixed_ver = "3.7.6S";
}
else if (
  ver == "3.9.2S" ||
  ver =~ "^3\.10.(0a|3)S$"
)
{
  cbi = "CSCue22753";
  fixed_ver = "3.10.4S";
}

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # metadata flow check
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*metadata flow$", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # IPv6 metadata flow check
    buf = cisco_command_kb_item("Host/Cisco/Config/show_metadata_flow_table_ipv6", "show metadata flow table ipv6");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^Flow\s+Proto\s+DPort\s+SPort", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the metadata flow feature is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
