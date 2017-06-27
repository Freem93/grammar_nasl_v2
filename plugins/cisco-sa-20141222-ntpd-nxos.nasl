#TRUSTED 9d46725f6bf289b5e81e9c14b0c09db99a05f0be71e4c68d0a59a87b4505719ac24634323933efb46b64c32415fc5213f3cb60cb5bd4894323063acdec56aabbdab5ecfb5650c8088d0ca6cb8a840a19960537c9b5e65245bb9e1b333a1584489d71241e59cfeed315c30e3fc9d1ecc787a5a24dfc4b4a6b9c850436dcc4a510276ce230a8d6e944f15430f84e4a819be894e773829645729d81a0375d437f7c75a197fc768e4db18acc68ba58a895b3e987f9d4f5dd75015173b39122f65495fb190ab6115ddae811fa6e12414761cc90525e144e46fdc0466bbf5ae137cce2684a158df04095487802a22def5e8338f6b618397e22e8806ab12c36bc86b59b8034489a85cee91178483e468d6967a314e160ee035f5af3f6c970e918bc66ac8ce0b8115b55159bb16cfff26b5871238599e31b5e347d53b93c5c46dfcc0700864f195f3f1e6d27865c72fa5f7cf08717ca86a51dbbaa36075ca393d2f47feb79be963fd98fa8526602adec334df44e666040ccb4a6d4fe4d511c8b2b7befb67a203b824bc6916712075cd3353257d5eaf7c493760c007f14c6e5e8804b24cc7cd3dd769ef70dd680ffbee5266604b19ada025ba11f409b37d748bb0dd808215a2c8a869f6322db60be5862864a04de431fa61a5eabf782362a3cbd266ad9438a5eef0763677e50248d5df6e3c335c1eb55b3543a5e3d1e8964929444aecc85
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81911);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/01");

  script_cve_id(
    "CVE-2014-9293",
    "CVE-2014-9294",
    "CVE-2014-9295",
    "CVE-2014-9296"
  );
  script_bugtraq_id(71757, 71758, 71761, 71762);
  script_osvdb_id(116066, 116067, 116068, 116069, 116070, 116074);
  script_xref(name:"CERT", value:"852879");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus26859");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus26870");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus26873");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus26875");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus26882");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus29415");

  script_name(english:"Cisco NX-OS Multiple ntpd Vulnerabilities");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of NX-OS software that
is affected by the following vulnerabilities :

  - Errors exist related to weak cryptographic pseudorandom
    number generation (PRNG), the functions 'ntp_random' and
    and 'config_auth', and the 'ntp-keygen' utility. A
    man-in-the-middle attacker can exploit these to disclose
    sensitive information. (CVE-2014-9293, CVE-2014-9294)

  - Multiple stack-based buffer overflow errors exist in the
    Network Time Protocol daemon (ntpd), which a remote
    attacker can exploit to execute arbitrary code or cause
    a denial of service by using a specially crafted packet.
    (CVE-2014-9295)

  - An error exists in the 'receive' function in the Network
    Time Protocol daemon (ntpd) that allows denial of
    service attacks. (CVE-2014-9296)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141222-ntpd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79cfbf7f");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/534319");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in the noted Cisco
bugs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus and MDS
if (device != 'Nexus' && device != "MDS")
  audit(AUDIT_HOST_NOT, "affected");

flag     = 0;
override = 0;
cbid     = NULL;

########################################
# CSCus26882 / Model 1000V
########################################
if (device == "Nexus" && model =~ "^1[0-9][0-9][0-9]([Vv])$")
{
  if (version == "5.2(1)SV3(1.1)") { flag++; fix = "5.2(1)SV3(1.3)"; }
  else if (version == "5.2(1)SV3(1.2)") { flag++; fix = "5.2(1)SV3(1.3)"; }
  # from cvrf
  else if (version == "4.0(4)SV1(1)") { flag++; fix = "See solution."; }
  else if (version == "4.0(4)SV1(2)") { flag++; fix = "See solution."; }
  else if (version == "4.0(4)SV1(3)") { flag++; fix = "See solution."; }
  else if (version == "4.0(4)SV1(3a)") { flag++; fix = "See solution."; }
  else if (version == "4.0(4)SV1(3b)") { flag++; fix = "See solution."; }
  else if (version == "4.0(4)SV1(3c)") { flag++; fix = "See solution."; }
  else if (version == "4.0(4)SV1(3d)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV1(4)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV1(4a)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV1(4b)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV1(5.1)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV1(5.1a)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV1(5.2)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV1(5.2b)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV2(1.1)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV2(1.1a)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV2(2.1)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)SV2(2.1a)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)VSG1(1)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)VSG1(2)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)VSG1(3.1)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)VSG1(5.1)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)VSG1(5.1a)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)VSG1(5.2)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)SM1(5.1)") { flag++; fix = "See solution."; }
  cbid = "CSCus26882";
}

########################################
# CSCus26875 / Model 3000
########################################
else if (device == "Nexus" && model =~ "^3[0-9][0-9][0-9]$")
{
  if (version == "6.0(2)U5(1)") { flag++; fix = "6.0(2)A4(3.43) / 6.0(2)A4(4) / 6.0(2)A6(0.44) / 6.0(2)A6(1) / 6.0(2)U4(3.43) / 6.0(2)U4(4) / 6.0(2)U6(0.44) / 6.0(2)U6(1)"; }
  # from cvrf
  else if (version == "5.0(3)U1(1)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U1(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U1(1b)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U1(1d)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U1(2)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U1(2a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U2(1)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U2(2)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U2(2a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U2(2b)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U2(2c)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U2(2d)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U3(1)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U3(2)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U3(2a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U3(2b)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U4(1)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1b)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1c)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1d)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1e)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1f)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1g)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)U5(1h)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U1(1)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U1(1a)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U1(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U1(3)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U1(4)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U2(1)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U2(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U2(3)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U2(4)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U2(5)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U2(6)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U3(1)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U3(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U3(3)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U3(4)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U3(5)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U4(1)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U4(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U4(3)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)U5(1)") { flag++; fix = "See solution."; }
  cbid = "CSCus26875";
}

########################################
#  CSCus26859 / Model 4000
########################################
else if (device == "Nexus" && model =~ "^4[0-9][0-9][0-9]$")
{
  if (version == "4.1(2)E1(1o)") { flag++; fix = "See solution."; }
  # from cvrf
  else if (version == "4.1(2)E1(1)") { flag++; fix = "See solution."; }
  else if (version == "4.1(2)E1(1b)") { flag++; fix = "See solution."; }
  else if (version == "4.1(2)E1(1d)") { flag++; fix = "See solution."; }
  else if (version == "4.1(2)E1(1e)") { flag++; fix = "See solution."; }
  else if (version == "4.1(2)E1(1f)") { flag++; fix = "See solution."; }
  else if (version == "4.1(2)E1(1g)") { flag++; fix = "See solution."; }
  else if (version == "4.1(2)E1(1h)") { flag++; fix = "See solution."; }
  else if (version == "4.1(2)E1(1i)") { flag++; fix = "See solution."; }
  else if (version == "4.1(2)E1(1j)") { flag++; fix = "See solution."; }
  cbid = "CSCus26859";
}

########################################
#  CSCus26870 / Model 50xx
#  Note that CSCus26873 is a duplicate
########################################
else if (device == "Nexus" && model =~ "^50[0-9][0-9]$")
{
  # from cvrf
  if (version == "4.0(0)N1(1a)") { flag++; fix = "See solution."; }
  else if (version == "4.0(0)N1(2)") { flag++; fix = "See solution."; }
  else if (version == "4.0(0)N1(2a)") { flag++; fix = "See solution."; }
  else if (version == "4.0(1a)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "4.0(1a)N1(1a)") { flag++; fix = "See solution."; }
  else if (version == "4.0(1a)N2(1)") { flag++; fix = "See solution."; }
  else if (version == "4.0(1a)N2(1a)") { flag++; fix = "See solution."; }
  else if (version == "4.1(3)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "4.1(3)N1(1a)") { flag++; fix = "See solution."; }
  else if (version == "4.1(3)N2(1)") { flag++; fix = "See solution."; }
  else if (version == "4.1(3)N2(1a)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)N2(1)") { flag++; fix = "See solution."; }
  else if (version == "4.2(1)N2(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(2)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "5.0(2)N2(1)") { flag++; fix = "See solution."; }
  else if (version == "5.0(2)N2(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)N1(1c)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)N2(1)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)N2(2)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)N2(2a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)N2(2b)") { flag++; fix = "See solution."; }
  else if (version == "5.1(3)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "5.1(3)N1(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.1(3)N2(1)") { flag++; fix = "See solution."; }
  else if (version == "5.1(3)N2(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.1(3)N2(1b)") { flag++; fix = "See solution."; }
  else if (version == "5.1(3)N2(1c)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(1b)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(2)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(2a)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(3)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(4)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(5)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(6)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(7)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(8)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)N1(8a)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N1(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N1(2a)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(1)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(1b)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(3)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(4)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(5)") { flag++; fix = "See solution."; }
  else if (version == "7.0(0)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "7.0(1)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "7.0(2)N1(1)") { flag++; fix = "See solution."; }
  else if (version == "7.0(3)N1(1)") { flag++; fix = "See solution."; }
  cbid = "CSCus26870 and CSCus26873";
}

########################################
#  CSCus26870 / Model 55xx, 56xx and 60xx
#  Note that CSCus26873 is a duplicate
########################################
else if (
  device == "Nexus" &&
  (model =~ "^5[56][0-9][0-9]$" || model =~ "^60[0-9][0-9]$")
)
{
  # from cvrf
  if (version == "5.0.0") { flag++; fix = "See solution."; }
  else if (version == "5.0.1") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N1(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N1(2a)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(1)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(1b)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(3)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(4)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)N2(5)") { flag++; fix = "See solution."; }
  else if (version == "7.0(0)N1(1)") { flag++; fix = "7.0(6)N1(1)"; }
  else if (version == "7.0(1)N1(1)") { flag++; fix = "7.0(6)N1(1)"; }
  else if (version == "7.0(2)N1(1)") { flag++; fix = "7.0(6)N1(1)"; }
  else if (version == "7.0(3)N1(1)") { flag++; fix = "7.0(6)N1(1)"; }
  else if (version == "8.6Base") { flag++; fix = "See solution."; }
  else if (version == "8.7Base") { flag++; fix = "See solution."; }
  else if (version == "9.0Base") { flag++; fix = "See solution."; }
  else if (version == "9.2.1") { flag++; fix = "See solution."; }
  else if (version == "9.2Base") { flag++; fix = "See solution."; }
  cbid = "CSCus26870 and CSCus26873";
}

########################################
#  CSCus26870 / Model 7xxx
#  Note that CSCus26873 is a duplicate
########################################
else if (device == "Nexus" && model =~ "^7[0-9][0-9][0-9]$")
{
  # from cvrf
  if (version == "4.1.(2)") { flag++; fix = "See solution."; }
  else if (version == "4.1.(3)") { flag++; fix = "See solution."; }
  else if (version == "4.1.(4)") { flag++; fix = "See solution."; }
  else if (version == "4.1.(5)") { flag++; fix = "See solution."; }
  else if (version == "4.2(3)") { flag++; fix = "See solution."; }
  else if (version == "4.2(4)") { flag++; fix = "See solution."; }
  else if (version == "4.2(6)") { flag++; fix = "See solution."; }
  else if (version == "4.2(8)") { flag++; fix = "See solution."; }
  else if (version == "4.2.(2a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(2a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(3)") { flag++; fix = "See solution."; }
  else if (version == "5.0(5)") { flag++; fix = "See solution."; }
  else if (version == "5.1(1)") { flag++; fix = "See solution."; }
  else if (version == "5.1(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.1(3)") { flag++; fix = "See solution."; }
  else if (version == "5.1(4)") { flag++; fix = "See solution."; }
  else if (version == "5.1(5)") { flag++; fix = "See solution."; }
  else if (version == "5.1(6)") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)") { flag++; fix = "See solution."; }
  else if (version == "5.2(3a)") { flag++; fix = "See solution."; }
  else if (version == "5.2(4)") { flag++; fix = "See solution."; }
  else if (version == "5.2(5)") { flag++; fix = "See solution."; }
  else if (version == "5.2(7)") { flag++; fix = "See solution."; }
  else if (version == "5.2(9)") { flag++; fix = "See solution."; }
  else if (version == "6.0(1)") { flag++; fix = "See solution."; }
  else if (version == "6.0(2)") { flag++; fix = "See solution."; }
  else if (version == "6.0(3)") { flag++; fix = "See solution."; }
  else if (version == "6.0(4)") { flag++; fix = "See solution."; }
  else if (version == "6.1(1)") { flag++; fix = "See solution."; }
  else if (version == "6.1(2)") { flag++; fix = "See solution."; }
  else if (version == "6.1(3)") { flag++; fix = "See solution."; }
  else if (version == "6.1(4)") { flag++; fix = "See solution."; }
  else if (version == "6.1(4a)") { flag++; fix = "See solution."; }
  else if (version == "6.2(2)") { flag++; fix = "6.2(12)"; }
  else if (version == "6.2(2a)") { flag++; fix = "6.2(12)"; }
  else if (version == "6.2(6)") { flag++; fix = "6.2(12)"; }

  # 'Known Affected Releases' portion of bug page
  else if (version == "7.2(0)ZD(0.1)") { flag++; fix = "See solution."; }
  else if (version == "7.2(0)ZN(0.4)") { flag++; fix = "See solution."; }
  else if (version == "7.9(0)ZD(0.4)") { flag++; fix = "See solution."; }
  else if (version == "8.0(0.1)") { flag++; fix = "See solution."; }
  else if (version == "9.9(9)") { flag++; fix = "See solution."; }
  cbid = "CSCus26870 and CSCus26873";
}

########################################
#  CSCus26870 / Device MDS
#  Note that CSCus26873 is a duplicate
########################################
else if (device == "MDS")
{
  # from cvrf
  if (version == "5.0(1a)") { flag++; fix = "See solution."; }
  else if (version == "5.0(4)") { flag++; fix = "See solution."; }
  else if (version == "5.0(4b)") { flag++; fix = "See solution."; }
  else if (version == "5.0(4c)") { flag++; fix = "See solution."; }
  else if (version == "5.0(4d)") { flag++; fix = "See solution."; }
  else if (version == "5.0(7)") { flag++; fix = "See solution."; }
  else if (version == "5.0Base") { flag++; fix = "See solution."; }
  else if (version == "5.2(1)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2(2)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2(2a)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2(2d)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2(6)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2(6a)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2(6b)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2(8)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2(8d)") { flag++; fix = "5.2(8f)"; }
  else if (version == "5.2Base") { flag++; fix = "5.2(8f)"; }
  else if (version == "6.2(1)") { flag++; fix = "See solution."; }
  else if (version == "6.2(7)") { flag++; fix = "See solution."; }
  else if (version == "6.2Base") { flag++; fix = "See solution."; }
  cbid = "CSCus26870 and CSCus26873";
}

########################################
#  CSCus29415 / Model 9xxx
########################################
else if (device == "Nexus" && model =~ "^9[0-9][0-9][0-9]$")
{
  if (version == "7.0(3)I1(0.197)") { flag++; fix = "See solution."; }
  # from cvrf
  else if (version == "11.0(1b)") { flag++; fix = "See solution."; }
  else if (version == "11.0(1c)") { flag++; fix = "See solution."; }
  else if (version == "6.1(2)I2(1)") { flag++; fix = "See solution."; }
  else if (version == "6.1(2)I2(2)") { flag++; fix = "See solution."; }
  else if (version == "6.1(2)I2(2a)") { flag++; fix = "See solution."; }
  else if (version == "6.1(2)I2(2b)") { flag++; fix = "See solution."; }
  else if (version == "6.1(2)I2(3)") { flag++; fix = "See solution."; }
  else if (version == "6.1(2)I3(3)") { flag++; fix = "See solution."; }
  cbid = "CSCus29415";
}

# Check status of NTPd locally if possible
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status",
                                "show ntp status");
    if (check_cisco_result(buf))
    {
      if (
        "Distribution: Disabled" >!< buf
        &&
        "system poll" >< buf
        &&
        "Clock is" >< buf
      ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + cbid +
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra: cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
