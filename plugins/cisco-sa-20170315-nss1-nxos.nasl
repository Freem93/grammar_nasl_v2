#TRUSTED ad47e5559724fb863ea2d4386289511b0bd99bfb50ce336e92102df3661c015935d01370518239b590a6f08e59dc6498f7d384c13d34c97b2f103b0bfe7e916f9d715b1c17997d466f10c6f3789e9a2912fdca7e3d8d124c27cff560cc32fed7517b0d465db607f16be5be7bbd18fe97c159513ab19a19a966aaaf8d38604a8bb63a7535494b2044c70d6f0975ed4893203fd308d0644bf4cb9ffc1cdf845104c85560fc5fb44d181d17039aa297cfabef448cb1d0da5644b4aad37742fa8beb1cb399edb615eb3f542ba923b3761791bc13930533caae431c0c34f7d990a13b057c61cba3c17de4e4cd5478cfb8fe91b23a98b912be52999683317b68dbc3da28f3abde731c80f55fc0180e221eb48776b5996fe05faad09b846d15184d6367404af04ab392e85c470a6a52c2ab005987c9bfce3cd89047771d5c99946de4d411442059fb541be772c4224a21c6c73256184aa001b092dd88b07ce07bbbf90ec02281726f921f58f18be5e285e4225df74caf36a32ba6566d0386e527051a11e30d0c4cd8b310811bc36bece88b62e1032311a450e362b71dd7e55af8d8f73123a2de83d951865c3e1a85056c871f0f99d2ad53a74eec9d94e7d6801315c283edfbcff6fcc48c98088ee1fb17511ab67b2c9a664b420d51f0fc8151bf453975abe48684d5b15769e317e7d40adec94ba7a9dd7a3fdf52b2a09f16b6afe15119
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99372);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/15");

  script_cve_id("CVE-2017-3879");
  script_bugtraq_id(96920);
  script_osvdb_id(153824);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy25824");
  script_xref(name:"IAVA", value:"2017-A-0096");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170315-nss1");

  script_name(english:"Cisco NX-OS Failed Authentication Handling Remote DoS (cisco-sa-20170315-nss1)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the remote login functionality due to improper
handling of failed authentication during login. An unauthenticated,
remote attacker can exploit this to cause Telnet or SSH to terminate.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-nss1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7a1d656");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy25824.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

flag = 0;
cbid = FALSE;

########################################
# Model 9k
########################################
if (model =~ "^9[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "7.0(3)I3(1)"         ) flag = TRUE;
  else if(version == "8.3(0)CV(0.342)") flag = TRUE;
  else if(version == "8.3(0)CV(0.345)") flag = TRUE;
  cbid = "CSCuy25824";
}

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

# Check for telnet feature
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^(\s+)?feature telnet", string:buf) || !preg(multiline:TRUE, pattern:"^(\s+)?no feature ssh", string:buf))
    flag = TRUE;
  }
}
else if (cisco_needs_enable(buf)) override = TRUE;

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbid
  );
}
else audit(AUDIT_HOST_NOT, "affected");
