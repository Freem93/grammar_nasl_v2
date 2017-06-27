#TRUSTED 56f5820049c0d233395b17b3a2e36735f0771ed5d946645876df5f8fa362b79028673e372005251e3ac7a8753eb894202bd703eb0e0059dfd7fe626bc730dce1713c7782311efabaceb9627e86cfbed29a46d10186a65300454e7fe2c42678a7c035f5a850ef5040edf9482b836427d08dd926fedd8960d90a701eef31c75b8cc714d7d31f62896e19ab1ca0343944a2f58fd69cc6b2c8b25d259be27440d17db33d0d07fb822106f1cde2bf542f4c9b6042c52d2723b98b3fe6d2fb34199b44b0283124ae33c7fe02044cbfdc4e608b1dc323edbd0cda3983bb07481c9c4fb275e3088180b5401aec595fb6ff73c93052aa90a1f25bd5232452983c51dba6a08985d1c72657243761532ae88edfddf34819dab295aeef88e81abad170f24ce178856e21eb5cc37e6447f9c13e1018a4beb146a2e5def2e93313af6493a5cf5219485ccfa89c4303d38407a4ce40fd0e90ce20682a40ed5575dc45d3f914c65a640cc74043ab2c28fdfd117eaafb7a56db80e60e9e6c316ca61f40c6f94d2fce1ba6a1d3a69b1dbccdf5435f2bfd2a9a139e10bc5b89fd27fe4236450a98ef167880cf5a0a9f617e9a3f84fc758bbc2cff536b7feccfbe967a0b9ff0bd303aaf38533e7dbf3a9254227143a62d85b677be8b96de800580df660f00fb04cd74ceeb2a1339da8627342dfa18522e8cefd39ecdcf8cde546350b0dad7236940f10f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90308);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/27");

  script_cve_id("CVE-2016-1351");
  script_bugtraq_id(85309);
  script_osvdb_id(136247);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv11993");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-lisp");

  script_name(english:"Cisco NX-OS Malformed LISP Packet DoS (CSCuv11993)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco NX-OS software running on the remote device is
affected by a denial of service vulnerability in the implementation of
the Locator/ID Separation Protocol (LISP) due to improper input
validation when a malformed LISP packet is received. An
unauthenticated, remote attacker can exploit this, via a crafted
packet, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-lisp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3df085d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv11993.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
cmds = make_list();

if (
  version == "4.1.(2)" ||
  version == "4.1.(3)" ||
  version == "4.1.(4)" ||
  version == "4.1.(5)" ||
  version == "4.2(3)" ||
  version == "4.2(4)" ||
  version == "4.2(6)" ||
  version == "4.2(8)" ||
  version == "4.2.(2a)" ||
  version == "5.0(2a)" ||
  version == "5.0(3)" ||
  version == "5.0(5)" ||
  version == "5.1(1)" ||
  version == "5.1(1a)" ||
  version == "5.1(3)" ||
  version == "5.1(4)" ||
  version == "5.1(5)" ||
  version == "5.1(6)" ||
  version == "5.2(1)" ||
  version == "5.2(3a)" ||
  version == "5.2(4)" ||
  version == "5.2(5)" ||
  version == "5.2(7)" ||
  version == "5.2(9)" ||
  version == "6.0(1)" ||
  version == "6.0(2)" ||
  version == "6.0(3)" ||
  version == "6.0(4)" ||
  version == "6.1(1)" ||
  version == "6.1(2)" ||
  version == "6.1(3)" ||
  version == "6.1(4)" ||
  version == "6.1(4a)" ||
  version == "6.2(10)" ||
  version == "6.2(12)" ||
  version == "6.2(14)S1" ||
  version == "6.2(2)" ||
  version == "6.2(2a)" ||
  version == "6.2(6)" ||
  version == "6.2(6b)" ||
  version == "6.2(8)" ||
  version == "6.2(8a)" ||
  version == "6.2(8b)" ||
  version == "7.2(0)N1(0.1)"
)
{
  flag     = FALSE;
  override = FALSE;

  if (get_kb_item("Host/local_checks_enabled"))
  {
    # Check for M1 modules
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module_m1", "show module | include M1");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"powered-up(\s|$)", string:buf))
      {
        flag = TRUE;
        cmds = make_list(cmds, "show module | include M1");
      }
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
  # Check for LISP enabled
  if (flag || override)
  {
    flag = FALSE;
    override = FALSE;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_feature_lisp", "show feature | include lisp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enabled(\s|$)", string:buf))
      {
        flag = TRUE;
        cmds = make_list(cmds, "show feature | include lisp");
      }
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
  # Check for LISP on interfaces
  if (flag || override)
  {
    flag = FALSE;
    override = FALSE;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_lisp", "show ip lisp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enabled(\s|$)", string:buf))
      {
        flag = TRUE;
        cmds = make_list(cmds, "show ip lisp");
      }
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCuv11993",
    cmds     : cmds
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS software", version);
