#TRUSTED 77fe7c6763618e0ee3a05d51a71b7fa04b4b6aa79de474e66c723495860af3b6eac95b488e13239291fb8a44dce2bfc604aadd3ed4f3fd03938f1a8aa68cc24cca46996b872c239447a4a48991ff990d8f5e8f5445f4a41d4b7c0307ac7c73f86f19f2f7f816c45d1799b504c638645a3140560716884628dfc569a70ca6a1dc83eabde9e7cd51f386db3e7ef6aea5f95e2e352b13a33d5b4c75cf83f2a4f2f57cbf61e5dfb3d14effc8142ee59d0ce30a727e0daf8c20ca78ed4354ee4d6ed3b877f888ded87d8a6cdb508821b2cab788f9f0d038ebe2aeaff4285e7291c6f745a909cc49a2849bbde3ed8a281393ab23221cd07648f3932b014ab1f8018cef5bda4c84b18f8b2b9922939492ab4a584b3a4d3cb859842110d887be3c628546c8df4ebca3536e8e0d4b76dae5a60117b169f1da6fcdc58dc5ad8c258cea9bd9bacacd04d311aca90aef44fb2e781a2154f9b8f5406cdceeb56a70184d7ed7cf089dc2d8ba06b88f905070c1f093af1c0b1e2863146b126a28eb97050058e10b6ff93405f206e1fe91463c9e67470d543ac664ecbd1089ff4150db6ab956637bebc614bd637194367292ab2fc3c262f562f08e8f04843593759fcf4cdfeb00aa07fc5e31d11a63ea83bdab6787353ed9c686cb3c6c4c3f371103a70e64738716dd7b6c6c2a38bf05586fbac7244cb2921e5f2a30e6bffe82bb96ed6596e52196
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82573);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0650");
  script_bugtraq_id(73335);
  script_osvdb_id(119949);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup70579");
  script_xref(name:"CISCO-SA",value:"cisco-sa-20150325-mdns");

  script_name(english:"Cisco IOS XE Software mDNS Gateway DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is affected by a vulnerability in the multicast DNS gateway
component due to improper validation of mDNS packets. A remote,
unauthenticated attacker, by sending crafted packets to UDP port 5353,
can exploit this to cause a device reload, leading to a denial of
service.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup70579");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff1e945");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37820");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCup70579.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
flag = 0;
override = 0;

if (
  version =~ "^3.3.[01]SE$" ||
  version =~ "^3.5.[0-3]E$" ||
  version =~ "^3.6.0E$" ||
  version =~ "^3.10.([0123]|1x[bc]|2a)S$" ||
  version =~ "^3.11.[012]S$" ||
  version =~ "^3.12.[01]S$" ||
  version =~ "^3.13.0a?S$"
) flag++;

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_socket",
                              "show ip socket");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+5353\s", string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override++;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCup70579' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
