#TRUSTED 6d3835f256e043ef9acd7ef682a8c0a384fdeb10c9fc84be7395886373d2de1efbe9b9d5ffeb7570d9d0520594b8752fcff9fb5aaa094c9cf71008f1f83e8ea1f7cc1cd28c9be15f55a85360988aeed1586bcd5c6b6f3f07da9cac16de50d31bdb8db972d4feb63c93d498382a6bbeb0bccd3de93c3d87a08c3adb9a1b25c8289050d47e21e42b53b05faee0ac0ac59a585e4dcf67360a95e8a83317e4210496b94d2fbe31d7625d2dff1876f3de734c1ee5b6b63ac11f3c68e71ba3877d49c38970e3f291abddf621a725da8a1e0bef4efc94c6c752b7dfca9ffcf15fe5ba6747a66e9cb6dfbe999d7b05e7148c89cfed40b3765207be54c288adbbff7d000c5c812d4247445f726e1abea5bf8f89909af9a2515b9be260f193d51fa6ab6d4116b9a218ffa49602de67f6706a30335b6d7c251dc3b8a021fdb8b997e1bc65b35600b4f24d0f06087fcd2b3b021c1aa624ef33972756bbc9d3dd63b81041d2615e0d2e641c2f4e10569506c182650478787cd434193ea328afa1b3ab399ebd9840d1abfe1b5f32b833b9006aef29982ddb69507286aa478352ad593cbfbb7b9bb1b9c5976ef7917aa2d0a6bac5a860804c5c2b243ee56e6ac1374cc200714fc4b350bf769254d8a7c38951e86cc440180b20cbb07e75102899d7eae204fbab3e251b3f74c6b9f14143d34d1a03baa40aef854afeb0954abc3f778bbfdaa2347a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86250);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/03");

  script_cve_id("CVE-2015-6280");
  script_osvdb_id(127980);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus73013");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-sshpk");

  script_name(english:"Cisco IOS XE SSHv2 RSA-Based User Authentication Bypass (CSCus73013)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and is configured for SSHv2 RSA-based user authentication. It
is, therefore, affected by a flaw in the SSHv2 protocol implementation
of the public key authentication method. An unauthenticated, remote
attacker can exploit this, via a crafted private key, to bypass
authentication mechanisms. In order to exploit this vulnerability an
attacker must know a valid username configured for RSA-based user
authentication and the public key configured for that user.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-sshpk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?072064d6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus73013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag     = 0;
override = FALSE;

if (version =='3.6.0E') flag++;
if (version =='3.6.0aE') flag++;
if (version =='3.6.0bE') flag++;
if (version =='3.6.1E') flag++;
if (version =='3.6.2E') flag++;
if (version =='3.6.2aE') flag++;
if (version =='3.7.0E') flag++;
if (version =='3.10.0S') flag++;
if (version =='3.10.01S') flag++;
if (version =='3.10.0aS') flag++;
if (version =='3.10.1S') flag++;
if (version =='3.10.2S') flag++;
if (version =='3.10.3S') flag++;
if (version =='3.10.4S') flag++;
if (version =='3.10.5S') flag++;
if (version =='3.11.0S') flag++;
if (version =='3.11.1S') flag++;
if (version =='3.11.2S') flag++;
if (version =='3.11.3S') flag++;
if (version =='3.12.0S') flag++;
if (version =='3.12.1S') flag++;
if (version =='3.12.2S') flag++;
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE software", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-begin-ip-ssh-pubkey-chain", "show running-config | begin ip ssh pubkey-chain");
  if (check_cisco_result(buf))
  {
    if (
      "ip ssh pubkey-chain" >< buf &&
      "username" >< buf
    )
      flag = 1;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCus73013' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
