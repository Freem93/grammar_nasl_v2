#TRUSTED a89ca1390b515de6250387a992e1ad7d995a31650d7396dfe314978b550be5c6d460073bf5edcdd48b0402b9849244e3744b68a94dcf83e36151e92b0edece81d19e49cd859d4aefa47de5191982c17df66e3f9a2ecfbd86f2948e21fd828a160bf75032ba5b7a05622466cf086ef27de2aa305bd9ae6ef0a082d13aad3dc534a2dc3462600851904a486e6592fb27a7ee649310f8008cb3e0c77440fbc6a5564e9b7ea28037fa940655cbd78972fc0f0b4f2eabb1baec3af5291ce05d526d21db24cafb188635ef7fe538c332c67c4cc3f4c9f1c53d94f4c72209641ed46032e7813a74fefb4a300b9c339664702172357af36fa03af7178c7fc0f0c52ff8ea357b33d3281843fce4c179d9a54effafd9c0c62b99621bbb594b3a23da15ed4f842ee4916fdc3f6758c5f0405f2811fbcce6140b47aaa2581e860a8679377bb4198d9f806b7a5d0fb93a63d242b8aeaff86ab49079c22bc3e6cdfaf3a554193b6e3c0723996fa20e72ebfa7a764d4bd69eb9b95ffcab5ec021c432fa37f24e12d5d7723d1017eca3b493723213782bc0ea9863c391210c02b61816300faa80a39607506e31aa06b1bbf2bbbb464fbb9157fb97bd944d48d28aa178fda8db40ce1b6f46881df4f683fa19598f24c01851a323cc67cbe75abb41f6604cf149e5d3f8dcff24a75ea4b069643f893fba206f4a418f98d2ccc1a06be7d16a01470026
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97992);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/29");

  script_cve_id("CVE-2017-3881");
  script_bugtraq_id(96960);
  script_osvdb_id(153995);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd48893");
  script_xref(name:"IAVA", value:"2017-A-0073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170317-cmp");

  script_name(english:"Cisco IOS XE Cluster Management Protocol Telnet Option Handling RCE (cisco-sa-20170317-cmp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by a remote
code execution vulnerability in the Cluster Management Protocol (CMP)
subsystem due to improper handling of CMP-specific Telnet options. An
unauthenticated, remote attacker can exploit this by establishing a
Telnet session with malformed CMP-specific telnet options, to execute
arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb68237");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd48893. Alternatively, as a workaround, disable the Telnet
protocol for incoming connections.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
cmds = make_list();

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check for vuln version
# these were extracted from the CVRF
if (
  ver == "2.3.0" ||
  ver == "2.3.1t" ||
  ver == "2.3.2" ||
  ver == "2.3.1" ||
  ver == "2.4.0" ||
  ver == "2.4.1" ||
  ver == "2.4.2" ||
  ver == "2.4.3" ||
  ver == "2.2.1" ||
  ver == "2.2.2" ||
  ver == "2.2.3" ||
  ver == "2.2.0" ||
  ver == "2.5.0" ||
  ver == "2.5.1" ||
  ver == "2.6.0" ||
  ver == "2.6.1" ||
  ver == "3.1.1SG" ||
  ver == "3.1.0SG" ||
  ver == "3.2.0SG" ||
  ver == "3.2.2SG" ||
  ver == "3.2.3SG" ||
  ver == "3.2.4SG" ||
  ver == "3.2.5SG" ||
  ver == "3.2.6SG" ||
  ver == "3.2.7SG" ||
  ver == "3.2.8SG" ||
  ver == "3.2.9SG" ||
  ver == "3.2.10SG" ||
  ver == "3.2.11SG" ||
  ver == "3.2.0XO" ||
  ver == "3.3.0SG" ||
  ver == "3.3.2SG" ||
  ver == "3.3.1SG" ||
  ver == "3.3.0XO" ||
  ver == "3.3.1XO" ||
  ver == "3.3.2XO" ||
  ver == "3.4.0SG" ||
  ver == "3.4.2SG" ||
  ver == "3.4.1SG" ||
  ver == "3.4.3SG" ||
  ver == "3.4.4SG" ||
  ver == "3.4.5SG" ||
  ver == "3.4.6SG" ||
  ver == "3.4.7SG" ||
  ver == "3.4.7aSG" ||
  ver == "3.4.8SG" ||
  ver == "3.4.9SG" ||
  ver == "3.5.0E" ||
  ver == "3.5.1E" ||
  ver == "3.5.2E" ||
  ver == "3.5.3E" ||
  ver == "3.6.0E" ||
  ver == "3.6.1E" ||
  ver == "3.6.2E" ||
  ver == "3.6.3E" ||
  ver == "3.6.4E" ||
  ver == "3.6.5E" ||
  ver == "3.6.6E" ||
  ver == "3.6.5aE" ||
  ver == "3.6.5bE" ||
  ver == "3.6.7E" ||
  ver == "3.3.0SQ" ||
  ver == "3.3.1SQ" ||
  ver == "3.4.0SQ" ||
  ver == "3.4.1SQ" ||
  ver == "3.7.0E" ||
  ver == "3.7.1E" ||
  ver == "3.7.2E" ||
  ver == "3.7.3E" ||
  ver == "3.7.4E" ||
  ver == "3.7.5E" ||
  ver == "3.5.0SQ" ||
  ver == "3.5.1SQ" ||
  ver == "3.5.2SQ" ||
  ver == "3.5.3SQ" ||
  ver == "3.5.4SQ" ||
  ver == "3.5.5SQ" ||
  ver == "3.8.0E" ||
  ver == "3.8.1E" ||
  ver == "3.8.2E" ||
  ver == "3.8.3E" ||
  ver == "3.8.4E" ||
  ver == "3.8.0EX" ||
  ver == "3.9.0E" ||
  ver == "3.9.1E"
)
  flag++;

if(!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", ver);

# Check if the CMP subsystem is present, then
# Check that device is configured to accept incoming Telnet connections
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # CMP subsystem check
  command = "show subsys class protocol | include ^cmp";
  command_kb = "Host/Cisco/Config/" + command;
  buf = cisco_command_kb_item(command_kb, command);
  if (check_cisco_result(buf))
  {
    if (preg(string:buf, pattern:"^cmp\s+Protocol", multiline:TRUE))
    {
      # cmp subsystem is not present, so we can audit out as the
      # device is not vuln
      audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", ver + " without the CMP subsystem");
    }
    # otherwise the CMP subsystem is present so we continue on to check
    # if incoming telnet is enabled
    cmds = make_list(cmds, command);
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # check that the device is configured to accept incoming Telnet connections
  # from the advisory
  command = "show running-config | include ^line vty|transport input";
  command_kb = "Host/Cisco/Config/" + command;
  buf = cisco_command_kb_item(command_kb, command);
  if (check_cisco_result(buf))
  {
    # if transport input lists "all" or "telnet", we are vuln
    # otherwise, if there is a "line vty" that is not followed by a
    # transport input line, we are vuln
    # otherwise, we are not vuln
    if (preg(string:buf, pattern:"^\s+transport input.*(all|telnet).*", multiline:TRUE))
    {
      flag = 1;
      cmds = make_list(cmds, command);
    }
    else
    {
      lines = split(buf, keep:FALSE);
      for (i = 0; i < max_index(lines); i++)
      {
        line = lines[i];
        if ((i+1) >= max_index(lines))
          next_line = "";
        else
          next_line = lines[i+1];

        if (line =~ "^line vty" && next_line !~ "^\s+transport input")
        {
          flag = 1;
          cmds = make_list(cmds, command);
          break;
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # no CMP subsystem, no telnet enabled = not vuln
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : 'CSCvd48893',
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
