#TRUSTED afb0fe55a5d4c07082cce6a6415a23a9e6769575b3d0b9a9dcdf1253161db390a701c7a4f7d2a9a70aec9e3e39cb115d45bf11818c0b7084c89c322ad27d6bfcd9a20a26ac73c02804167c02b62426b50161d9b279ae6517eae0f17193a2606dd6856049a82c599e04df7c7241b3336bfe21f74850d6dc81403a441f474a8603cc712784d9ddf6be8bf876009080cc32cc204ba5b42b7d066def4262332fda57d776dee6d170e17517d23664bbbc02a87dfdfefb119c432543db3ab9234a8bade711fd32d49e6275ba233edf5ec9c5b2718243fb7f06f6f47189b9afea815a9b7db1e0fcd521c2b5a6fc2936decce09ebb90ee8d8a5e20c4936edd14b362a0ff52e00b34d71560284db76d9fd5709bcfc785a1b3ba6c65acde643961b8f6d0c71c76e35587ac25c0c6025773a763ee05efb5e258b767600a3874e6bd57effac36b3d9e12925e63b728b6e7519cf956619fffaf7246a28fd7d0b02400b32c50c481f7221b6a02ef9ea5f14a36c0f1ac6dc4a94b4aa89f6c819c8e91f97c9645ea6a5651aa0b91fb983be5e086a23d7f8ceeaa20719e8b1ff4db4eb6026ba9634959714da44615503b6c432dcb05309036970bf4e39d393a4e0e9436cf18a07cf68de7664b89dc5ff312b6dd2cba3b013c7305ec1d48503faa7ab81028a819f26307b46afa5500d15d091228ae41cc9b41cea8f24b8d111659590f14f8ad09431b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94109);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/20");

  script_cve_id("CVE-2016-1453");
  script_bugtraq_id(93409);
  script_osvdb_id(145189);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy95701");
  script_xref(name:"IAVA", value:"2016-A-0274");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-otv");

  script_name(english:"Cisco NX-OS OTV GRE Packet Header Parameter Handling RCE (cisco-sa-20161005-otv)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a remote code execution
vulnerability in the Overlay Transport Virtualization (OTV) generic
routing encapsulation (GRE) feature due to improper validation of the
size of OTV packet header parameters. An unauthenticated, remote
attacker can exploit this, via long parameters in a packet header, to
cause a denial of service condition or the execution of arbitrary
code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-otv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3d6721f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy95701");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco advisory
cisco-sa-20161005-otv. Alternatively, as a workaround, configure an
Access Control List (ACL) to drop malformed OTV control packets.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device","Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
if (device != 'Nexus' || (model !~ '^7[07]{1}[0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, "Nexus model 7000 / 7700");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");
flag = FALSE;

if ( version == "4.1(2)" ) flag = TRUE;
if ( version == "4.1(3)" ) flag = TRUE;
if ( version == "4.1(4)" ) flag = TRUE;
if ( version == "4.1(5)" ) flag = TRUE;
if ( version == "4.2(2a)" ) flag = TRUE;
if ( version == "4.2(3)" ) flag = TRUE;
if ( version == "4.2(4)" ) flag = TRUE;
if ( version == "4.2(6)" ) flag = TRUE;
if ( version == "4.2(8)" ) flag = TRUE;
if ( version == "5.0(2a)" ) flag = TRUE;
if ( version == "5.0(3)" ) flag = TRUE;
if ( version == "5.0(5)" ) flag = TRUE;
if ( version == "5.1(1)" ) flag = TRUE;
if ( version == "5.1(1a)" ) flag = TRUE;
if ( version == "5.1(3)" ) flag = TRUE;
if ( version == "5.1(4)" ) flag = TRUE;
if ( version == "5.1(5)" ) flag = TRUE;
if ( version == "5.1(6)" ) flag = TRUE;
if ( version == "5.2(1)" ) flag = TRUE;
if ( version == "5.2(3a)" ) flag = TRUE;
if ( version == "5.2(4)" ) flag = TRUE;
if ( version == "5.2(5)" ) flag = TRUE;
if ( version == "5.2(7)" ) flag = TRUE;
if ( version == "5.2(9)" ) flag = TRUE;
if ( version == "6.0(1)" ) flag = TRUE;
if ( version == "6.0(2)" ) flag = TRUE;
if ( version == "6.0(3)" ) flag = TRUE;
if ( version == "6.0(4)" ) flag = TRUE;
if ( version == "6.1(1)" ) flag = TRUE;
if ( version == "6.1(2)" ) flag = TRUE;
if ( version == "6.1(3)" ) flag = TRUE;
if ( version == "6.1(4)" ) flag = TRUE;
if ( version == "6.1(4a)" ) flag = TRUE;
if ( version == "6.1(5)" ) flag = TRUE;
if ( version == "6.2(2)" ) flag = TRUE;
if ( version == "6.2(2a)" ) flag = TRUE;
if ( version == "6.2(6)" ) flag = TRUE;
if ( version == "6.2(6b)" ) flag = TRUE;
if ( version == "6.2(8)" ) flag = TRUE;
if ( version == "6.2(8a)" ) flag = TRUE;
if ( version == "6.2(8b)" ) flag = TRUE;
if ( version == "6.2(10)" ) flag = TRUE;
if ( version == "6.2(12)" ) flag = TRUE;
if ( version == "6.2(14)" ) flag = TRUE;
if ( version == "6.2(14)S1" ) flag = TRUE;
if ( version == "7.2(0)N1(0.1)" ) flag = TRUE;
if ( version == "7.3(0)D1(1)" ) flag = TRUE;

if (!flag) audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS software", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # Check for OTV feature
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^(\s+)?(feature otv|otv join-interface)", string:buf))
    flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : 'CSCuy95701',
    cmds     : make_list('show running-config')
  );
} else audit(AUDIT_HOST_NOT, "affected");
