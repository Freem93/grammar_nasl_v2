#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94070);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-0721");
  script_bugtraq_id(93410);
  script_osvdb_id(145185);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum35502");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw78669");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw79754");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux88492");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-nxaaa");
  script_xref(name:"IAVA", value:"2016-A-0274");

  script_name(english:"Cisco NX-OS SSH Connection Negotiation Remote Command Execution (cisco-sa-20161005-nxaaa)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of NX-OS that is affected
by a remote command execution vulnerability in the SSH subsystem due
to improper processing of parameters passed during the negotiation of
an SSH connection. An authenticated, remote attacker can exploit this
to bypass authentication, authorization, and account restrictions,
allowing the attacker to execute arbitrary commands on the device
command-line interface in the context of a privileged user role.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-nxaaa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0647e25a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20161005-nxaaa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

flag = 0;
cbid = FALSE;

########################################
# Model 1k
########################################
if (model =~ "^1[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "4.0(4)SV1(1)"         ) flag = TRUE;
  else if(version == "4.0(4)SV1(2)"    ) flag = TRUE;
  else if(version == "4.0(4)SV1(3)"    ) flag = TRUE;
  else if(version == "4.0(4)SV1(3a)"   ) flag = TRUE;
  else if(version == "4.0(4)SV1(3b)"   ) flag = TRUE;
  else if(version == "4.0(4)SV1(3c)"   ) flag = TRUE;
  else if(version == "4.0(4)SV1(3d)"   ) flag = TRUE;
  else if(version == "4.2(1)SV1(4)"    ) flag = TRUE;
  else if(version == "4.2(1)SV1(4a)"   ) flag = TRUE;
  else if(version == "4.2(1)SV1(4b)"   ) flag = TRUE;
  else if(version == "4.2(1)SV1(5.1)"  ) flag = TRUE;
  else if(version == "4.2(1)SV1(5.1a)" ) flag = TRUE;
  else if(version == "4.2(1)SV1(5.2)"  ) flag = TRUE;
  else if(version == "4.2(1)SV1(5.2b)" ) flag = TRUE;
  else if(version == "4.2(1)SV2(1.1)"  ) flag = TRUE;
  else if(version == "4.2(1)SV2(1.1a)" ) flag = TRUE;
  else if(version == "4.2(1)SV2(2.1)"  ) flag = TRUE;
  else if(version == "4.2(1)SV2(2.1a)" ) flag = TRUE;
  else if(version == "5.2(1)SM1(5.1)"  ) flag = TRUE;
  # Specifically from bug
  else if(version == "9.2(1)SP1(4.8)"  ) flag = TRUE;
  cbid = "CSCuw79754";
}
########################################
# Model 3k
########################################
else if (model =~ "^3[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "5.0(3)U1(1)"       ) flag = TRUE;
  else if(version == "5.0(3)U1(1a)" ) flag = TRUE;
  else if(version == "5.0(3)U1(1b)" ) flag = TRUE;
  else if(version == "5.0(3)U1(1d)" ) flag = TRUE;
  else if(version == "5.0(3)U1(2)"  ) flag = TRUE;
  else if(version == "5.0(3)U1(2a)" ) flag = TRUE;
  else if(version == "5.0(3)U2(1)"  ) flag = TRUE;
  else if(version == "5.0(3)U2(2)"  ) flag = TRUE;
  else if(version == "5.0(3)U2(2a)" ) flag = TRUE;
  else if(version == "5.0(3)U2(2b)" ) flag = TRUE;
  else if(version == "5.0(3)U2(2c)" ) flag = TRUE;
  else if(version == "5.0(3)U2(2d)" ) flag = TRUE;
  else if(version == "5.0(3)U3(1)"  ) flag = TRUE;
  else if(version == "5.0(3)U3(2)"  ) flag = TRUE;
  else if(version == "5.0(3)U3(2a)" ) flag = TRUE;
  else if(version == "5.0(3)U3(2b)" ) flag = TRUE;
  else if(version == "5.0(3)U4(1)"  ) flag = TRUE;
  else if(version == "5.0(3)U5(1)"  ) flag = TRUE;
  else if(version == "5.0(3)U5(1a)" ) flag = TRUE;
  else if(version == "5.0(3)U5(1b)" ) flag = TRUE;
  else if(version == "5.0(3)U5(1c)" ) flag = TRUE;
  else if(version == "5.0(3)U5(1d)" ) flag = TRUE;
  else if(version == "5.0(3)U5(1e)" ) flag = TRUE;
  else if(version == "5.0(3)U5(1f)" ) flag = TRUE;
  else if(version == "5.0(3)U5(1g)" ) flag = TRUE;
  else if(version == "5.0(3)U5(1h)" ) flag = TRUE;
  else if(version == "6.0(2)U1(1)"  ) flag = TRUE;
  else if(version == "6.0(2)U1(1a)" ) flag = TRUE;
  else if(version == "6.0(2)U1(2)"  ) flag = TRUE;
  else if(version == "6.0(2)U1(3)"  ) flag = TRUE;
  else if(version == "6.0(2)U1(4)"  ) flag = TRUE;
  else if(version == "6.0(2)U2(1)"  ) flag = TRUE;
  else if(version == "6.0(2)U2(2)"  ) flag = TRUE;
  else if(version == "6.0(2)U2(3)"  ) flag = TRUE;
  else if(version == "6.0(2)U2(4)"  ) flag = TRUE;
  else if(version == "6.0(2)U2(5)"  ) flag = TRUE;
  else if(version == "6.0(2)U2(6)"  ) flag = TRUE;
  else if(version == "6.0(2)U3(1)"  ) flag = TRUE;
  else if(version == "6.0(2)U3(2)"  ) flag = TRUE;
  else if(version == "6.0(2)U3(3)"  ) flag = TRUE;
  else if(version == "6.0(2)U3(4)"  ) flag = TRUE;
  else if(version == "6.0(2)U3(5)"  ) flag = TRUE;
  else if(version == "6.0(2)U4(1)"  ) flag = TRUE;
  else if(version == "6.0(2)U4(2)"  ) flag = TRUE;
  else if(version == "6.0(2)U4(3)"  ) flag = TRUE;
  else if(version == "6.0(2)U5(1)"  ) flag = TRUE;
  # Specifically from bug
  else if(version == "6.2(5)"       ) flag = TRUE;
  cbid = "CSCum35502";
}
########################################
# Model 4k
########################################
else if (model =~ "^4[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "4.1(2)E1(1)"        ) flag = TRUE;
  else if(version == "4.1(2)E1(1b)"  ) flag = TRUE;
  else if(version == "4.1(2)E1(1d)"  ) flag = TRUE;
  else if(version == "4.1(2)E1(1e)"  ) flag = TRUE;
  else if(version == "4.1(2)E1(1f)"  ) flag = TRUE;
  else if(version == "4.1(2)E1(1g)"  ) flag = TRUE;
  else if(version == "4.1(2)E1(1h)"  ) flag = TRUE;
  else if(version == "4.1(2)E1(1i)"  ) flag = TRUE;
  else if(version == "4.1(2)E1(1j)"  ) flag = TRUE;
    # Specifically from bug
  else if(version == "4.1(2)E1(1p)"  ) flag = TRUE;
  cbid = "CSCuw78669";
}
########################################
# Model 5k
########################################
else if (model =~ "^5[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "4.0(0)N1(1a)"      ) flag = TRUE;
  else if(version == "4.0(0)N1(2)"  ) flag = TRUE;
  else if(version == "4.0(0)N1(2a)" ) flag = TRUE;
  else if(version == "4.0(1a)N1(1)" ) flag = TRUE;
  else if(version == "4.0(1a)N1(1a)") flag = TRUE;
  else if(version == "4.0(1a)N2(1)" ) flag = TRUE;
  else if(version == "4.0(1a)N2(1a)") flag = TRUE;
  else if(version == "4.1(3)N1(1)"  ) flag = TRUE;
  else if(version == "4.1(3)N1(1a)" ) flag = TRUE;
  else if(version == "4.1(3)N2(1)"  ) flag = TRUE;
  else if(version == "4.1(3)N2(1a)" ) flag = TRUE;
  else if(version == "4.2(1)N1(1)"  ) flag = TRUE;
  else if(version == "4.2(1)N2(1)"  ) flag = TRUE;
  else if(version == "4.2(1)N2(1a)" ) flag = TRUE;
  else if(version == "5.0(2)N1(1)"  ) flag = TRUE;
  else if(version == "5.0(3)N1(1c)" ) flag = TRUE;
  else if(version == "5.0(2)N2(1)"  ) flag = TRUE;
  else if(version == "5.0(2)N2(1a)" ) flag = TRUE;
  else if(version == "5.0(3)N2(1)"  ) flag = TRUE;
  else if(version == "5.0(3)N2(2)"  ) flag = TRUE;
  else if(version == "5.0(3)N2(2a)" ) flag = TRUE;
  else if(version == "5.0(3)N2(2b)" ) flag = TRUE;
  else if(version == "5.1(3)N1(1)"  ) flag = TRUE;
  else if(version == "5.1(3)N1(1a)" ) flag = TRUE;
  else if(version == "5.1(3)N2(1)"  ) flag = TRUE;
  else if(version == "5.1(3)N2(1a)" ) flag = TRUE;
  else if(version == "5.1(3)N2(1b)" ) flag = TRUE;
  else if(version == "5.1(3)N2(1c)" ) flag = TRUE;
  else if(version == "5.2(1)N1(1)"  ) flag = TRUE;
  else if(version == "5.2(1)N1(1a)" ) flag = TRUE;
  else if(version == "5.2(1)N1(1b)" ) flag = TRUE;
  else if(version == "5.2(1)N1(2)"  ) flag = TRUE;
  else if(version == "5.2(1)N1(2a)" ) flag = TRUE;
  else if(version == "5.2(1)N1(3)"  ) flag = TRUE;
  else if(version == "5.2(1)N1(4)"  ) flag = TRUE;
  else if(version == "5.2(1)N1(5)"  ) flag = TRUE;
  else if(version == "5.2(1)N1(6)"  ) flag = TRUE;
  else if(version == "5.2(1)N1(7)"  ) flag = TRUE;
  else if(version == "5.2(1)N1(8)"  ) flag = TRUE;
  else if(version == "5.2(1)N1(8a)" ) flag = TRUE;
  else if(version == "6.0(2)N1(1)"  ) flag = TRUE;
  else if(version == "6.0(2)N1(2)"  ) flag = TRUE;
  else if(version == "6.0(2)N1(2a)" ) flag = TRUE;
  else if(version == "6.0(2)N2(1)"  ) flag = TRUE;
  else if(version == "6.0(2)N2(1b)" ) flag = TRUE;
  else if(version == "6.0(2)N2(2)"  ) flag = TRUE;
  else if(version == "6.0(2)N2(3)"  ) flag = TRUE;
  else if(version == "6.0(2)N2(4)"  ) flag = TRUE;
  else if(version == "6.0(2)N2(5)"  ) flag = TRUE;
  else if(version == "7.0(0)N1(1)"  ) flag = TRUE;
  else if(version == "7.0(1)N1(1)"  ) flag = TRUE;
  else if(version == "7.0(2)N1(1)"  ) flag = TRUE;
  else if(version == "7.0(3)N1(1)"  ) flag = TRUE;
      # Specifically from bug
  else if(version == "7.0(8)N1(0.310)" ) flag = TRUE;
  else if(version == "7.3(1)N1(0.37)"  ) flag = TRUE;
  cbid = "CSCux88492";
}
########################################
# Model 6k
########################################
else if (model =~ "^6[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "6.0(2)N1(2)"       ) flag = TRUE;
  else if(version == "6.0(2)N1(2a)" ) flag = TRUE;
  else if(version == "6.0(2)N2(1)"  ) flag = TRUE;
  else if(version == "6.0(2)N2(1b)" ) flag = TRUE;
  else if(version == "6.0(2)N2(2)"  ) flag = TRUE;
  else if(version == "6.0(2)N2(3)"  ) flag = TRUE;
  else if(version == "6.0(2)N2(4)"  ) flag = TRUE;
  else if(version == "6.0(2)N2(5)"  ) flag = TRUE;
  else if(version == "7.0(0)N1(1)"  ) flag = TRUE;
  else if(version == "7.0(1)N1(1)"  ) flag = TRUE;
  else if(version == "7.0(2)N1(1)"  ) flag = TRUE;
  else if(version == "7.0(3)N1(1)"  ) flag = TRUE;
  cbid = "CSCux88492";
}
########################################
# Model 7k
########################################
else if (model =~ "^7[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "4.1.(2)"       ) flag = TRUE;
  else if(version == "4.1.(3)"  ) flag = TRUE;
  else if(version == "4.1.(4)"  ) flag = TRUE;
  else if(version == "4.1.(5)"  ) flag = TRUE;
  else if(version == "4.2.(2a)" ) flag = TRUE;
  else if(version == "4.2(3)"   ) flag = TRUE;
  else if(version == "4.2(4)"   ) flag = TRUE;
  else if(version == "4.2(6)"   ) flag = TRUE;
  else if(version == "4.2(8)"   ) flag = TRUE;
  else if(version == "5.0(2a)"  ) flag = TRUE;
  else if(version == "5.0(3)"   ) flag = TRUE;
  else if(version == "5.0(5)"   ) flag = TRUE;
  else if(version == "5.1(1)"   ) flag = TRUE;
  else if(version == "5.1(1a)"  ) flag = TRUE;
  else if(version == "5.1(3)"   ) flag = TRUE;
  else if(version == "5.1(4)"   ) flag = TRUE;
  else if(version == "5.1(5)"   ) flag = TRUE;
  else if(version == "5.1(6)"   ) flag = TRUE;
  else if(version == "5.2(1)"   ) flag = TRUE;
  else if(version == "5.2(3a)"  ) flag = TRUE;
  else if(version == "5.2(4)"   ) flag = TRUE;
  else if(version == "5.2(5)"   ) flag = TRUE;
  else if(version == "5.2(7)"   ) flag = TRUE;
  else if(version == "5.2(9)"   ) flag = TRUE;
  else if(version == "6.0(1)"   ) flag = TRUE;
  else if(version == "6.0(2)"   ) flag = TRUE;
  else if(version == "6.0(3)"   ) flag = TRUE;
  else if(version == "6.0(4)"   ) flag = TRUE;
  else if(version == "6.1(1)"   ) flag = TRUE;
  else if(version == "6.1(2)"   ) flag = TRUE;
  else if(version == "6.1(3)"   ) flag = TRUE;
  else if(version == "6.1(4)"   ) flag = TRUE;
  else if(version == "6.1(4a)"  ) flag = TRUE;
  else if(version == "6.2(2)"   ) flag = TRUE;
  else if(version == "6.2(2a)"  ) flag = TRUE;
  else if(version == "6.2(6)"   ) flag = TRUE;
  else if(version == "6.2(6b)"  ) flag = TRUE;
  else if(version == "6.2(8)"   ) flag = TRUE;
  else if(version == "6.2(8a)"  ) flag = TRUE;
  else if(version == "6.2(8b)"  ) flag = TRUE;
  else if(version == "6.2(10)"  ) flag = TRUE;
  # Specifically from bug
  else if(version == "6.2(5)"   ) flag = TRUE;
  cbid = "CSCum35502";
}
########################################
# Model 9k
########################################
else if (model =~ "^9[0-9][0-9][0-9]([^0-9]|$)")
{
  if(version == "6.1(2)I2(1)"       ) flag = TRUE;
  else if(version == "6.1(2)I2(2)"  ) flag = TRUE;
  else if(version == "6.1(2)I2(2a)" ) flag = TRUE;
  else if(version == "6.1(2)I2(2b)" ) flag = TRUE;
  else if(version == "6.1(2)I2(3)"  ) flag = TRUE;
  else if(version == "6.1(2)I3(1)"  ) flag = TRUE;
  else if(version == "6.1(2)I3(2)"  ) flag = TRUE;
  else if(version == "6.1(2)I3(3)"  ) flag = TRUE;
  else if(version == "11.0(1b)"     ) flag = TRUE;
  else if(version == "11.0(1c)"     ) flag = TRUE;
  cbid = "CSCum35502";
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    version  : version,
    bug_id   : cbid
  );
}
else audit(AUDIT_HOST_NOT, "affected");
