#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83087);

  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/27 14:59:14 $");

  script_cve_id("CVE-2015-0658");
  script_bugtraq_id(73390);
  script_osvdb_id(120023);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur14589");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu06246");

  script_name(english:"Cisco NX-OS DHCP POAP Command Injection Vulnerability");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of NX-OS software that
is affected by a command injection vulnerability due to the PowerOn
Auto Provisioning (POAP) feature not properly validating the DHCP
options returned by POAP. An attacker on an adjacent network, using
crafted DHCP packets, can execute arbitrary commands as the root user
in response to the initial DHCP request made by the device during the
POAP process.");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=38062
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6a5f6f1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in Cisco bug ID CSCur14589 or
CSCuu06246.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/27");

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

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

flag     = 0;

# Bug only lists 7k but covers the 5/6/7/9 models (from support)
cbid     = "CSCur14589";
# Official first fixes for each model (from support)
n5kfix   = "7.1(0)N1(1)";
n6kfix   = "7.1(0)N1(1)";
n7kfix   = "6.2(10)";
n9kfix   = "6.1(2)I3(4)";
# First N3k fix
n3kfix   = "6.0(2)U6(1.33)";

########################################
# Model 3k
########################################
if (device == "Nexus" && model =~ "^3[0-9][0-9][0-9]$")
{
  # 3K has a different bug
  cbid = "CSCuu06246";
  if(version == "5.0(3)U3(1)"       ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U3(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U3(2a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U3(2b)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U4(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1b)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1c)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1d)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1e)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1f)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1g)" ) {flag += 1; fix = n3kfix;}
  else if(version == "5.0(3)U5(1h)" ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(1a)" ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(3)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U1(4)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(3)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(4)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(5)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U2(6)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(3)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(4)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U3(5)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U4(1)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U4(2)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U4(3)"  ) {flag += 1; fix = n3kfix;}
  else if(version == "6.0(2)U5(1)"  ) {flag += 1; fix = n3kfix;}
}

########################################
# Model 5k
########################################
else if (device == "Nexus" && model =~ "^5[0-9][0-9][0-9]$")
{
  if(version == "6.0(2)N1(1)"       ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N1(2)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N1(2a)" ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(1b)" ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(2)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(3)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(4)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "6.0(2)N2(5)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "7.0(0)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "7.0(1)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "7.0(2)N1(1)"  ) {flag += 1; fix = n5kfix;}
  else if(version == "7.0(3)N1(1)"  ) {flag += 1; fix = n5kfix;}
}

########################################
# Model 6k
########################################
else if (device == "Nexus" && model =~ "^6[0-9][0-9][0-9]$")
{
  if(version == "6.0(2)N1(2)"       ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N1(2a)" ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(1)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(1b)" ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(2)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(3)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(4)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "6.0(2)N2(5)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "7.0(0)N1(1)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "7.0(1)N1(1)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "7.0(2)N1(1)"  ) {flag += 1; fix = n6kfix;}
  else if(version == "7.0(3)N1(1)"  ) {flag += 1; fix = n6kfix;}
}

########################################
# Model 7k
########################################
else if (device == "Nexus" && model =~ "^7[0-9][0-9][0-9]$")
{
  if(version == "6.1(2)"       ) {flag += 1; fix = n7kfix;}
  else if(version == "6.1(3)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.1(4)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.1(4a)" ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(2)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(2a)" ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(6)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(6b)" ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(8)"  ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(8a)" ) {flag += 1; fix = n7kfix;}
  else if(version == "6.2(8b)" ) {flag += 1; fix = n7kfix;}
}

########################################
# Model 9k
########################################
else if (device == "Nexus" && model =~ "^9[0-9][0-9][0-9]$")
{
  if(version == "11.0(1b)"         ) {flag += 1; fix = n9kfix;}
  else if(version == "11.0(1c)"    ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(1)" ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(2)" ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(2a)") {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(2b)") {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I2(3)" ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I3(1)" ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I3(2)" ) {flag += 1; fix = n9kfix;}
  else if(version == "6.1(2)I3(3)" ) {flag += 1; fix = n9kfix;}
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
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
