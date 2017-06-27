#TRUSTED 0879b458a39b8efa7a5c707d798db868ac85e3ee890340072f17b4043ea8b535c647c4c9a7a1b433ab87317e1eb0fee0e525c8d63b7daadce16574620d8b11324eedc37bcba037db4731fa94915d5ca11d463f62061c2e6131eebe4a57cff0d5f2c0f1d1d8cad8b9c0bde4eec61902b9ca5eccf541c47f0531e09c21efcc461e11e9a09180c88e54459151646b98a8538915950c56ad3f9dcea18522a0aaa19412e80efd3e9424b531f2c9471261352803d200d288c18cbae4b2175ebf9e9a19471a9bd456bb43cf08f26c23645e53b78861acd69c41e02ce0c33ddbddd48a8ea0962250aba15a3b2a2ec8a3efaf5fa3cabf3287a99c6f2f333f9017e4923ea08bb4bfb7b9e3f9140681414811b66d736319b1f1ec7c2fa6ed5af469e822330ba462a7e71a7cac3727f9592ae14b0c6e6806f0ad70686ef4c6648f1421948f2e9388d97cc2778a14c13a97d3c06f8e593836252b34c69c2ce3991c1f0f94b544a465fbc2d5d5fdb1cc16b073468ee05cedee96ac8a6e21701dccf0698f370c63495fbc0c9ef97c90848169209b60d9ceb3418aadadd8828689fd94fbfcaeed5abb29c9b027f24b34abb12ef686e19529491b1a342a9ff4c6351c1e2bd567004e0515d4f9891c7daa3631f12aa0837ec73e14bfcd6a20572bada78c47ee2af7f366ce18a4632b16d09f7182568857cea4e6fc9ec598a257e861c89480cca80a32
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/csa/cisco-sa-20070124-crafted-ip-option.html
#

include("compat.inc");

if (description)
{
  script_id(71431);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

  script_cve_id("CVE-2007-0480");
  script_bugtraq_id(22211);
  script_osvdb_id(32092);
  script_xref(name:"CERT", value:"341288");
  script_xref(name:"CISCO-BUG-ID", value:"CSCeh52410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20070124-crafted-ip-option");

  script_name(english:"Crafted IP Option Vulnerability (cisco-sa-20070124-crafted-ip-option)");
  script_summary(english:"Checks IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco routers and switches running Cisco IOS XR software may be
vulnerable to a remotely exploitable crafted IP option Denial of Service
(DoS) attack.  Exploitation of the vulnerability may potentially allow
for arbitrary code execution.  The vulnerability may be exploited after
processing an Internet Control Message Protocol (ICMP) packet, Protocol
Independent Multicast version 2 (PIMv2) packet, Pragmatic General
Multicast (PGM) packet, or URL Rendezvous Directory (URD) packet
containing a specific crafted IP option in the packet\'s IP header.  No
other IP protocols are affected by this issue.  Cisco has made free
software available to address this vulnerability for affected
customers.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20070124-crafted-ip-option
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdec28c3");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070124-crafted-ip-option.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
cbi = "CSCeh52410";
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ((cisco_gen_ver_compare(a:version, b:"3.2.82.3") >= 0) && (cisco_gen_ver_compare(a:version, b:"3.3") == -1)) flag ++;
fixed_ver = "upgrade to 3.3.0.2 or later";


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory_all", "show inventory all");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"CRS-1", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv4_interface", "show ipv4 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"protocol is Up", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed Release : ' + version +
    '\n    Fixed Release     : ' + fixed_ver + '\n';

  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

