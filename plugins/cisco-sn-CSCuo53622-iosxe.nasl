#TRUSTED 72eecae1b6a0ed47ca10b0e5ba58ad5f304a644d6b0d1d7e9c7308dfdbb99df0784a66a2748c67949bd322a2803fb4018b717482aad067621056fb343f21eb0a88eda606be3c63530b29d5984f6a2ec328f09c1c3c9e20fb6d61c9de7d9c0349f4dd8cc67068a65eadc6330461aebced1e6493d2adcb9e86aa0aab5ff15d559b279c8fb3a6806581472407579cbb1228fdaa9fd6da6bb8097cf15e306dfeacd0ed042aa13527d64d6956d79f6ca140869e893416078ff99e57bf1ce8a08cfbcee14aa5c48fdb67ccf3b5a617c5c65f7e6f2053a2e66aa51f02161ba54e83bcf5463be506a8fc9a9b5ba35db26af93be565b7b02486c5dbfd34dde6d530f807e23aa728377db275789f3fe25de72052224f1171ce72818e8caa3424fce258556890da6f2e94a0c7a4f37cc23b68019e39890f39777fe9cf32ba6fa688d7f1111519313ecefce919ea5e9b383fba811f0a21922b9cfbfe70eed6404bb5b718d02ed31634ed87fcbde1cc7d67d02c19f3c34095ea354a34add193c1a71e5411f265f2621c15c3fc8d80e453951b304a0ecf9c65abeed22138c10b01b3fbea90925b435e3d792f63c8d0eeb05b9725f9515674cd2e2260b0fcdfee4a88cfd7780acf1ca5f62080908a0bd8016415313e32dfe4a512e39e0ae3e6979b91b1770cff571ff99b71b835d9f3e3cfcdaaf78fb6bb7aeea47c29cdab15c4724c63467c3d11
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82589);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/08/02");

  script_cve_id("CVE-2015-0644");
  script_bugtraq_id(73332);
  script_osvdb_id(119942);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo53622");

  script_name(english:"Cisco IOS XE AppNav Component RCE");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a vulnerability in the AppNav component due to the improper processing
of TCP packets. An unauthenticated, remote attacker, using a crafted
TCP packet, can exploit this to cause a device reload or to execute
arbitrary code in the forwarding engine.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30ea0b29");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo53622");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Per Bug CSCuo53622
if (
  !(
    "ASR1k"    >< model ||
    "ISR4400"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Bug (converted) and CVRF
if (version == "3.10.2S") flag++;

# CVRF
if (version == "3.8.0S")   flag++;
if (version == "3.8.0S")   flag++;
if (version == "3.8.1S")   flag++;
if (version == "3.8.2S")   flag++;
if (version == "3.9.1S")   flag++;
if (version == "3.9.0S")   flag++;
if (version == "3.10.0S")  flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.0aS") flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.9.2S")   flag++;
if (version == "3.11.0S")  flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_service-insertion_appnav-controller-group", "show service-insertion appnav-controller-group");
  if (check_cisco_result(buf))
  {
    if ("All AppNav Controller Groups in service context" >< buf )
    {
      lines = split(buf);
      count = max_index(buf);
      # Find 'Members:' line, followed by
      # two lines of IP addresses.
      for (i=0; i<count-2; i++)
      {
        if (
          lines[i] == "Members:"
          &&
          lines[i+1] =~ "^\d+\.\d+\.\d+\.\d+$"
          &&
          lines[i+2] =~ "^\d+\.\d+\.\d+\.\d+$"
        )
          flag = 1;
      }
    }
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuo53622' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
