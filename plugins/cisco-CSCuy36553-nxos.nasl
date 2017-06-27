#TRUSTED ab6a6dd625dd4b2465299ba47e4a4af6214f59af6edcf8b767ea449c5288c2d4de5f289cf96e9e3fbe073ab3007ed81af553c501ad02244b8aac3db302ea91ae7d9f344d12819f886647bba2481665db065b08ec1abfbf4ae6be5b5c3106ed6975a5f7f5fc9ea48d75968cd24b69098f90064fa034c386ecdb82febff7c06366423ee679896c1e18a5fc4f02597129ac6edc6c0f4f12d10c0492e1fcedb99b0df79429b89c5cdfccb1190369bc12b75dc67dff0b30fb85c258d485a389492d7607fd677531793c154cb41ec18f0ac62a540c1b4e9946417137b7a73ca655caf79dd6e2cf4fe82c702de733555c552dbfd24b12e29d8c6400200a2cb6e2d3630666cc3166eaaf0805d099b760f3746beb201aeb8d6049493677a40d846f483c63346b7851fdfbea485472834c621c1428ab7a3c4e75e33f40295411a306569ad3408247779dbb6227d3e1fef37b193a9914b7b9bf60bbc46dee4fc2cf671af705ee329d31f6d2bc07d163927dc21357d248e30ccdc21485bdd545a20003406dcd651828847db573ffad406323acbec1b7d5bd97f0535a635de39fafd90142fdc777dd62be506d2802c953c37aa9d6bb8912c03f712b91db04e496eedee6def004b5dc4015b21e7fdcaf6cf21b2921e96fe4941bca645eeddac0b30ed40e082c121ea7ad80ed23f4bf7d1876d9fd63b44efebacca7bd83b244ff5890aefce00e18
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93480);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/28");

  script_cve_id("CVE-2015-7547");
  script_bugtraq_id(83265);
  script_osvdb_id(134584);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160218-glibc");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy36553");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy38921");
  script_xref(name:"EDB-ID", value:"39454");
  script_xref(name:"EDB-ID", value:"40339");
  script_xref(name:"CERT", value:"457759");

  script_name(english:"Cisco Nexus 3000 / 9000 Series GNU C Library (glibc) getaddrinfo() RCE (cisco-sa-20160218-glibc)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco NX-OS software running on the remote device is
affected by a remote code execution vulnerability in the bundled
version of the GNU C Library (glibc) due to a stack-based buffer
overflow condition in the DNS resolver. An unauthenticated, remote
attacker can exploit this, via a crafted DNS response that triggers a
call to the getaddrinfo() function, to cause a denial of service
condition or the execution of arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160218-glibc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae76a668");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy36553");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy38921");
  # https://security.googleblog.com/2016/02/cve-2015-7547-glibc-getaddrinfo-stack.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94dd3376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version or install the relevant 
SMU patches referenced in Cisco bug ID CSCuy36553 / CSCuy38921.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/14");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

# only affects nexus 9000 series systems
# and the 3000 series systems listed in the advisory/bugs
if (
  device != 'Nexus' || 
  model !~ '^(3016|3048|3064|3132|3164|3172|3232|3264|31128|[9][0-9][0-9][0-9][0-9]?)([^0-9]|$)'
  ) audit(AUDIT_HOST_NOT, "affected");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

override = 0;
check_patch = 0;
vuln = 0;

if ((
  # Only CSCuy36553
  version =~ "^6\.1" ||
  version =~ "^7\.0\(3\)I1"
  ) && model =~ '^(3164|3232|3264|31128|9[0-9][0-9][0-9][0-9]?)([^0-9]|$)'
) vuln ++;
# CSCuy36553 & CSCuy38921
else if (
  version =~ "^7\.0\(3\)I2\(1[a-z]?\)" ||
  version == "7.0(3)I2(2)" ||
  version == "7.0(3)I3(1)"
) vuln ++;
else if ( version == "7.0(3)I2(2a)" || version == "7.0(3)I2(2b)" ) 
{
  # flag vuln in case we can't check for the patch.
  vuln ++;
  check_patch ++;
}
else audit(AUDIT_HOST_NOT, "affected");

# check for the patch on 7.0(3)I2(2[ab])
# audit if patched, assume vuln otherwise
if (check_patch && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_install_active", "show install active");
  if (check_cisco_result(buf))
  {
    # Modular products 2a - 2 patches
    # nxos.CSCuy36553_modular_sup-1.0.0-7.0.3.I2.2a.lib32_n9000
    # nxos.CSCuy36553_modular_lc-1.0.0-7.0.3.I2.2a.lib32_n9000
    if ( version == "7.0(3)I2(2a)" && model =~ "^(9504|9508|9516)")
    {
      if 
      ( 
        "CSCuy36553_modular_sup" >< buf && 
        "CSCuy36553_modular_lc" >< buf
      ) 
      audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patches are installed");
    }
    # ToR products 2a - 1 patch
    # nxos.CSCuy36553_TOR-1.0.0-7.0.3.I2.2a.lib32_n9000
    else if (version == "7.0(3)I2(2a)")
    {
      if ("CSCuy36553_TOR" >< buf) audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patch is installed");
    }
    # All products 2b - 2 patches
    # nxos.CSCpatch01-1.0.0-7.0.3.I2.2b.lib32_n9000
    # nxos.CSCuy36553-1.0.0-7.0.3.I2.2b.lib32_n9000
    else if ( version == "7.0(3)I2(2b)")
    {
      if 
      ( 
        "CSCpatch01" >< buf && 
        "CSCuy36553" >< buf
      ) 
      audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patches are installed");
    }
    
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fix               : see solution.' +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
