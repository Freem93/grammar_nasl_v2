#TRUSTED 8700d2d7df2531b1a85f66f4324192dcd76cefdf473c8fee5ad738c4ed4d7b621cd8f96d9b0bcac65bafe59596252e6628d681836c9814291ceedb5fd18bad1e322336275b95d4af84378c331d265cb559b3acadf483e77f79414b6fe093e1a1a0ca3050850051d4f7018470e50f6bad4277d27e01e632b7b646174ac3465bde8f6c5e29a95083ba295927dfb2646076660ec6e040150d0c6bce0d647096e6d7f005d49ae7d70e0a00ef7082f5c13b974e551332769fcdd50edc6d0e281699f37012fabb93fe1353adfd70c0d52d79e41466886ea371897105cf5f6a7df03a3789757299488b3a7768e0a554f39ae79c40fce0351dcc3e8ecaaaf5251c48ccf2d712e2f0d7e2b5657d81b5907a87d8382360ec1e2d2c828d71ed4cfdad3d91211f08f92b5d901825bc34a39a46b47ac57bbdc1a595a2768055cd878a61f5e7ab55477c534fa369da73cec2973564ee6cd66629a73f0d97da65432197662c95982babc4937a34ced712a252741a9e539e1f728899c97d55ad8fd0019ba6d99a737ab9beea6c4b5ebc6463dbea5a97f149140fe18c8163dabb57a75e415a16a4f41771b67e1938b05b3cbff3a69563e7d0e56de9ebaf8e16a4845dfd3fd76528c504c3edf2195356bf241277437f34916a031fe76cf201f731f58f7b2200f4f8be434670f0b0c2f4269106c3f0be16954d060483500f46827dd93cb873ea2f8f9d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97991);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/29");

  script_cve_id("CVE-2017-3881");
  script_bugtraq_id(96960);
  script_osvdb_id(153995);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd48893");
  script_xref(name:"IAVA", value:"2017-A-0073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170317-cmp");

  script_name(english:"Cisco IOS Cluster Management Protocol Telnet Option Handling RCE (cisco-sa-20170317-cmp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS software running on the remote device is affected by a remote code
execution vulnerability in the Cluster Management Protocol (CMP)
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
cmds = make_list();

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
# these were extracted from the CVRF
if (
  ver == "12.2(18)S" ||
  ver == "12.2(25)S" ||
  ver == "12.2(25)S1" ||
  ver == "12.1(22)EA8" ||
  ver == "12.1(11)EA1a" ||
  ver == "12.1(22)EA12" ||
  ver == "12.1(22)EA6" ||
  ver == "12.1(14)EA1" ||
  ver == "12.1(19)EA1b" ||
  ver == "12.1(22)EA3" ||
  ver == "12.1(14)EA1b" ||
  ver == "12.1(20)EA2" ||
  ver == "12.1(22)EA4a" ||
  ver == "12.1(14)EA1a" ||
  ver == "12.1(22)EA5a" ||
  ver == "12.1(22)EA13" ||
  ver == "12.1(22)EA1a" ||
  ver == "12.1(12c)EA1a" ||
  ver == "12.1(13)EA1c" ||
  ver == "12.1(22)EA1b" ||
  ver == "12.1(8)EA1c" ||
  ver == "12.1(22)EA5" ||
  ver == "12.1(22)EA10b" ||
  ver == "12.1(20)EA1a" ||
  ver == "12.1(22)EA11" ||
  ver == "12.1(22)EA7" ||
  ver == "12.1(22)EA1" ||
  ver == "12.1(13)EA1b" ||
  ver == "12.1(20)EA1" ||
  ver == "12.1(13)EA1" ||
  ver == "12.1(19)EA1a" ||
  ver == "12.1(22)EA2" ||
  ver == "12.1(19)EA1d" ||
  ver == "12.1(22)EA9" ||
  ver == "12.1(9)EA1" ||
  ver == "12.1(22)EA14" ||
  ver == "12.1(11)EA1" ||
  ver == "12.1(22)EA8a" ||
  ver == "12.1(12c)EA1" ||
  ver == "12.1(22)EA10a" ||
  ver == "12.1(19)EA1" ||
  ver == "12.1(19)EA1c" ||
  ver == "12.1(6)EA1" ||
  ver == "12.1(22)EA10" ||
  ver == "12.1(22)EA4" ||
  ver == "12.1(13)EA1a" ||
  ver == "12.1(22)EA6a" ||
  ver == "12.2(25)EW" ||
  ver == "12.2(20)EWA" ||
  ver == "12.2(25)EWA" ||
  ver == "12.2(25)EWA6" ||
  ver == "12.2(25)EWA5" ||
  ver == "12.2(25)EWA1" ||
  ver == "12.2(25)EWA10" ||
  ver == "12.2(25)EWA8" ||
  ver == "12.2(20)EWA1" ||
  ver == "12.2(25)EWA11" ||
  ver == "12.2(25)EWA9" ||
  ver == "12.2(25)EWA2" ||
  ver == "12.2(25)EWA14" ||
  ver == "12.2(25)EWA4" ||
  ver == "12.2(20)EWA3" ||
  ver == "12.2(25)EWA3" ||
  ver == "12.2(25)EWA7" ||
  ver == "12.2(20)EWA4" ||
  ver == "12.2(25)EWA12" ||
  ver == "12.2(25)EWA13" ||
  ver == "12.2(20)EWA2" ||
  ver == "12.2(35)SE" ||
  ver == "12.2(18)SE" ||
  ver == "12.2(20)SE" ||
  ver == "12.2(25)SE" ||
  ver == "12.2(37)SE" ||
  ver == "12.2(53)SE1" ||
  ver == "12.2(55)SE" ||
  ver == "12.2(25)SE2" ||
  ver == "12.2(40)SE2" ||
  ver == "12.2(46)SE" ||
  ver == "12.2(46)SE2" ||
  ver == "12.2(50)SE2" ||
  ver == "12.2(35)SE5" ||
  ver == "12.2(50)SE1" ||
  ver == "12.2(44)SE2" ||
  ver == "12.2(20)SE3" ||
  ver == "12.2(35)SE1" ||
  ver == "12.2(50)SE5" ||
  ver == "12.2(35)SE4" ||
  ver == "12.2(44)SE1" ||
  ver == "12.2(53)SE" ||
  ver == "12.2(37)SE1" ||
  ver == "12.2(25)SE3" ||
  ver == "12.2(35)SE3" ||
  ver == "12.2(44)SE4" ||
  ver == "12.2(55)SE3" ||
  ver == "12.2(55)SE2" ||
  ver == "12.2(40)SE" ||
  ver == "12.2(44)SE" ||
  ver == "12.2(52)SE" ||
  ver == "12.2(58)SE" ||
  ver == "12.2(50)SE3" ||
  ver == "12.2(55)SE1" ||
  ver == "12.2(35)SE2" ||
  ver == "12.2(18)SE1" ||
  ver == "12.2(40)SE1" ||
  ver == "12.2(25)SE1" ||
  ver == "12.2(20)SE1" ||
  ver == "12.2(44)SE6" ||
  ver == "12.2(44)SE3" ||
  ver == "12.2(53)SE2" ||
  ver == "12.2(52)SE1" ||
  ver == "12.2(46)SE1" ||
  ver == "12.2(20)SE2" ||
  ver == "12.2(54)SE" ||
  ver == "12.2(44)SE5" ||
  ver == "12.2(50)SE4" ||
  ver == "12.2(50)SE" ||
  ver == "12.2(20)SE4" ||
  ver == "12.2(58)SE1" ||
  ver == "12.2(55)SE4" ||
  ver == "12.2(58)SE2" ||
  ver == "12.2(55)SE5" ||
  ver == "12.2(55)SE6" ||
  ver == "12.2(55)SE7" ||
  ver == "12.2(55)SE8" ||
  ver == "12.2(55)SE9" ||
  ver == "12.2(55)SE10" ||
  ver == "12.2(55)SE11" ||
  ver == "12.1(14)AZ" ||
  ver == "12.2(20)EU" ||
  ver == "12.2(20)EU1" ||
  ver == "12.2(20)EU2" ||
  ver == "12.2(20)EX" ||
  ver == "12.2(44)EX" ||
  ver == "12.2(40)EX3" ||
  ver == "12.2(40)EX" ||
  ver == "12.2(52)EX" ||
  ver == "12.2(44)EX1" ||
  ver == "12.2(40)EX2" ||
  ver == "12.2(40)EX1" ||
  ver == "12.2(55)EX" ||
  ver == "12.2(46)EX" ||
  ver == "12.2(52)EX1" ||
  ver == "12.2(55)EX1" ||
  ver == "12.2(55)EX2" ||
  ver == "12.2(55)EX3" ||
  ver == "12.2(58)EX" ||
  ver == "12.2(25)SEB" ||
  ver == "12.2(25)SEB2" ||
  ver == "12.2(25)SEB1" ||
  ver == "12.2(25)SEB4" ||
  ver == "12.2(25)SEB3" ||
  ver == "12.2(25)SEA" ||
  ver == "12.2(25)EY" ||
  ver == "12.2(46)EY" ||
  ver == "12.2(55)EY" ||
  ver == "12.2(25)EY1" ||
  ver == "12.2(53)EY" ||
  ver == "12.2(25)EY3" ||
  ver == "12.2(37)EY" ||
  ver == "12.2(25)EY2" ||
  ver == "12.2(25)EY4" ||
  ver == "12.2(25)EZ" ||
  ver == "12.2(25)EZ1" ||
  ver == "12.2(58)EZ" ||
  ver == "12.2(53)EZ" ||
  ver == "12.2(55)EZ" ||
  ver == "12.2(60)EZ4" ||
  ver == "12.2(60)EZ5" ||
  ver == "12.2(25)SEC" ||
  ver == "12.2(25)SEC2" ||
  ver == "12.2(25)SEC1" ||
  ver == "12.2(31)SG" ||
  ver == "12.2(25)SG" ||
  ver == "12.2(37)SG" ||
  ver == "12.2(44)SG" ||
  ver == "12.2(50)SG3" ||
  ver == "12.2(31)SG1" ||
  ver == "12.2(53)SG" ||
  ver == "12.2(31)SG3" ||
  ver == "12.2(50)SG6" ||
  ver == "12.2(53)SG1" ||
  ver == "12.2(137)SG" ||
  ver == "12.2(46)SG" ||
  ver == "12.2(25)SG1" ||
  ver == "12.2(53)SG2" ||
  ver == "12.2(50)SG5" ||
  ver == "12.2(37)SG1" ||
  ver == "12.2(53)SG3" ||
  ver == "12.2(50)SG8" ||
  ver == "12.2(25)SG3" ||
  ver == "12.2(50)SG2" ||
  ver == "12.2(40)SG" ||
  ver == "12.2(25)SG2" ||
  ver == "12.2(54)SG1" ||
  ver == "12.2(44)SG1" ||
  ver == "12.2(50)SG1" ||
  ver == "12.2(52)SG" ||
  ver == "12.2(54)SG" ||
  ver == "12.2(144)SG" ||
  ver == "12.2(31)SG2" ||
  ver == "12.2(50)SG" ||
  ver == "12.2(25)SG4" ||
  ver == "12.2(50)SG7" ||
  ver == "12.2(53)SG4" ||
  ver == "12.2(50)SG4" ||
  ver == "12.2(46)SG1" ||
  ver == "12.2(53)SG5" ||
  ver == "12.2(53)SG6" ||
  ver == "12.2(53)SG7" ||
  ver == "12.2(53)SG8" ||
  ver == "12.2(53)SG9" ||
  ver == "12.2(53)SG10" ||
  ver == "12.2(53)SG11" ||
  ver == "12.2(25)FX" ||
  ver == "12.2(25)FY" ||
  ver == "12.2(25)SEF1" ||
  ver == "12.2(25)SEF2" ||
  ver == "12.2(25)SEF3" ||
  ver == "12.2(25)SEE" ||
  ver == "12.2(25)SEE1" ||
  ver == "12.2(25)SEE3" ||
  ver == "12.2(25)SEE4" ||
  ver == "12.2(25)SEE2" ||
  ver == "12.2(25)SED" ||
  ver == "12.2(25)SED1" ||
  ver == "12.2(31)SGA" ||
  ver == "12.2(31)SGA3" ||
  ver == "12.2(31)SGA2" ||
  ver == "12.2(31)SGA10" ||
  ver == "12.2(31)SGA5" ||
  ver == "12.2(31)SGA4" ||
  ver == "12.2(31)SGA11" ||
  ver == "12.2(31)SGA6" ||
  ver == "12.2(31)SGA1" ||
  ver == "12.2(31)SGA7" ||
  ver == "12.2(31)SGA8" ||
  ver == "12.2(31)SGA9" ||
  ver == "12.2(25)SEG" ||
  ver == "12.2(25)SEG1" ||
  ver == "12.2(25)SEG3" ||
  ver == "12.2(25)FZ" ||
  ver == "12.2(52)XO" ||
  ver == "12.2(54)XO" ||
  ver == "12.2(40)XO" ||
  ver == "12.2(44)SQ" ||
  ver == "12.2(44)SQ2" ||
  ver == "12.2(50)SQ2" ||
  ver == "12.2(50)SQ1" ||
  ver == "12.2(50)SQ" ||
  ver == "12.2(50)SQ3" ||
  ver == "12.2(50)SQ4" ||
  ver == "12.2(50)SQ5" ||
  ver == "12.2(50)SQ6" ||
  ver == "12.2(50)SQ7" ||
  ver == "15.0(1)XO1" ||
  ver == "15.0(1)XO" ||
  ver == "15.0(2)XO" ||
  ver == "15.0(1)EY" ||
  ver == "15.0(1)EY1" ||
  ver == "15.0(1)EY2" ||
  ver == "15.0(2)EY" ||
  ver == "15.0(2)EY1" ||
  ver == "15.0(2)EY2" ||
  ver == "15.0(2)EY3" ||
  ver == "12.2(54)WO" ||
  ver == "15.0(1)SE" ||
  ver == "15.0(2)SE" ||
  ver == "15.0(1)SE1" ||
  ver == "15.0(1)SE2" ||
  ver == "15.0(1)SE3" ||
  ver == "15.0(2)SE1" ||
  ver == "15.0(2)SE2" ||
  ver == "15.0(2)SE3" ||
  ver == "15.0(2)SE4" ||
  ver == "15.0(2)SE5" ||
  ver == "15.0(2)SE6" ||
  ver == "15.0(2)SE7" ||
  ver == "15.0(2)SE8" ||
  ver == "15.0(2)SE9" ||
  ver == "15.0(2a)SE9" ||
  ver == "15.0(2)SE10" ||
  ver == "15.0(2)SE11" ||
  ver == "15.0(2)SE10a" ||
  ver == "15.1(1)SG" ||
  ver == "15.1(2)SG" ||
  ver == "15.1(1)SG1" ||
  ver == "15.1(1)SG2" ||
  ver == "15.1(2)SG1" ||
  ver == "15.1(2)SG2" ||
  ver == "15.1(2)SG3" ||
  ver == "15.1(2)SG4" ||
  ver == "15.1(2)SG5" ||
  ver == "15.1(2)SG6" ||
  ver == "15.1(2)SG7" ||
  ver == "15.1(2)SG8" ||
  ver == "15.1(2)SG7a" ||
  ver == "15.0(2)SG" ||
  ver == "15.0(2)SG1" ||
  ver == "15.0(2)SG2" ||
  ver == "15.0(2)SG3" ||
  ver == "15.0(2)SG4" ||
  ver == "15.0(2)SG5" ||
  ver == "15.0(2)SG6" ||
  ver == "15.0(2)SG7" ||
  ver == "15.0(2)SG8" ||
  ver == "15.0(2)SG9" ||
  ver == "15.0(2)SG10" ||
  ver == "15.0(2)SG11" ||
  ver == "15.0(2)EX" ||
  ver == "15.0(2)EX1" ||
  ver == "15.0(2)EX2" ||
  ver == "15.0(2)EX3" ||
  ver == "15.0(2)EX4" ||
  ver == "15.0(2)EX5" ||
  ver == "15.0(2)EX8" ||
  ver == "15.0(2a)EX5" ||
  ver == "15.0(2)EX10" ||
  ver == "15.3(3)S9" ||
  ver == "15.0(2)EC" ||
  ver == "15.0(2)EB" ||
  ver == "15.2(1)E" ||
  ver == "15.2(2)E" ||
  ver == "15.2(1)E1" ||
  ver == "15.2(3)E" ||
  ver == "15.2(1)E2" ||
  ver == "15.2(1)E3" ||
  ver == "15.2(2)E1" ||
  ver == "15.2(4)E" ||
  ver == "15.2(3)E1" ||
  ver == "15.2(2)E2" ||
  ver == "15.2(2a)E1" ||
  ver == "15.2(2)E3" ||
  ver == "15.2(3)E2" ||
  ver == "15.2(3a)E" ||
  ver == "15.2(3)E3" ||
  ver == "15.2(3m)E2" ||
  ver == "15.2(4)E1" ||
  ver == "15.2(3m)E3" ||
  ver == "15.2(2)E4" ||
  ver == "15.2(2)E5" ||
  ver == "15.2(4)E2" ||
  ver == "15.2(4m)E1" ||
  ver == "15.2(5)E" ||
  ver == "15.2(4)E3" ||
  ver == "15.2(5a)E" ||
  ver == "15.2(5)E1" ||
  ver == "15.2(5b)E" ||
  ver == "15.2(4m)E3" ||
  ver == "15.2(2)E5a" ||
  ver == "15.2(5c)E" ||
  ver == "15.2(5a)E1" ||
  ver == "15.2(4)E4" ||
  ver == "15.0(2)EZ" ||
  ver == "15.2(1)EY" ||
  ver == "15.0(2)EJ" ||
  ver == "15.0(2)EJ1" ||
  ver == "15.2(5)EX" ||
  ver == "15.2(2)EB" ||
  ver == "15.2(2)EB1" ||
  ver == "15.2(2)EB2" ||
  ver == "15.0(2)SQD" ||
  ver == "15.0(2)SQD1" ||
  ver == "15.0(2)SQD2" ||
  ver == "15.0(2)SQD3" ||
  ver == "15.2(4)EC1"
)
  flag++;

if(!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS", ver);

# Check that device is configured to accept incoming Telnet connections
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
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
      cmds = make_list(command);
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
          cmds = make_list(command);
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS", ver);
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
