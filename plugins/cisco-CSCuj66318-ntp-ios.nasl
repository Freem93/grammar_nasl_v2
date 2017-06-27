#TRUSTED aa871161d2bf4b64051d751c10b09a9087fc0d26f2aad448214595da4cc05b6f3aaa88d9145455218335f7b539f6ffae5d5e9fbfd76e3d0bafefc8dfc28ed459f74e45b7f1188fb71e974a73d8ed4efaa3cd18ea7d5ac3614386fa5a3db1474d56017b5358ba2c71631c08ae38a219ad7a2843f66ae0f81ec7916224aa220b7c0559f09011adfbbdde6c05ee72ee8ad5447f080d47e67225bfa72c28128058fa4ead5a3f4ff3ae432128757856926850d8a233cc9fcd713a669b34e493f9c73155ea8f382b9a69f5b8382d208350f06881467fb108c406e9dc5d79f21f200ebbf2e430c5d9b89844a313636d08543dbd4fd87c08bd33fab2e9e06696cdca3826bdc0c0eac5777ee6dc96955c19cf940fda6d49c3b9d16a88a01bdaca6e09eca57508fccb2fb32f9635bd4f45c30edbd21f8dad9cff724192b5adb7f5aa16519b5358036f27b53dcf632837287e0ee968abf35dccf2c4c3f205266c3d3c0edbfffa18b29e9b4562197097d8f27477cfbbf63fcaec0afc9bf4c68bfdd4840bed8f1c7bdd287dd3bd0102b10231ccc441ed9a00d9e46e7dc7b3ec5f9ab22c693bef135fc8d2acddc96580b94c527a12ed50abccd2b6bbfd14d99075a7e4abae5c9f9eb782490c451a7e84b014427893497a0e086dca5e63373f007d7997551577956dc65e146cb7d3bac0d3c431675a15161088880b2ff1ed2cf6ba5fece6fb9d6d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77052);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3309");
  script_bugtraq_id(68463);
  script_osvdb_id(108862);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj66318");

  script_name(english:"Cisco IOS NTP Information Disclosure (CSCuj66318)");
  script_summary(english:"Checks IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device potentially contains an issue with the 'ntp
access-group' which could allow a remote attacker to bypass the NTP
access group and query an NTP server configured to deny-all requests.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3309
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?854f9178");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuj66318.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Per the advisory, IOS affected:
# 15.2M
# 15.2(4)M
# 15.4T
# 15.4(1)T
# Mappings were also added from IOS XE
# No specific hardware conditions
# No workarounds
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
flag = 0;
if (
  version =~ "^15\.2\(1\)S[1-2]?$" || #IOS-XE Mapping for 3.5S  .0, .1, .2
  version =~ "^15\.2\(2\)S[1-2]?$" || #IOS-XE Mapping for 3.6S  .0, .1, .2
  version =~ "^15\.2\(4\)S[1-4]?$" || #IOS-XE Mapping for 3.7S  .0, .1, .2, .3, .4
  version =~ "^15\.3\(1\)S[1-2]?$" || #IOS-XE Mapping for 3.8S  .0, .1, .2
  version =~ "^15\.3\(2\)S1?$"     || #IOS-XE Mapping for 3.9S  .0, .1
  version =~ "^15\.3\(3\)S[1-2]?$" || #IOS-XE Mapping for 3.10S .0, .1, .2
  version == "15.3(3)S0a"          || #IOS-XE Mapping for 3.10.0aS
  version =~ "^15\.4\(1\)S[1-2]$"  || #IOS-XE Mapping for 3.11  .1, .2
  version == "15.2M"               ||
  version == "15.2(4)M"            ||
  version == "15.4T"               ||
  version == "15.4(1)T"
) flag++;

override = 0;
if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  # Check if NTP actually enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      "ntp master" >< buf           ||
      "ntp peer" >< buf             ||
      "ntp broadcast client" >< buf ||
      "ntp multicast client" >< buf
    ) flag++;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuj66318' +
    '\n  Installed release : ' + version +
    '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
