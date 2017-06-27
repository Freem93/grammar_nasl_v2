#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70068);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_bugtraq_id(57911, 58523, 58524, 58525, 58526);
  script_osvdb_id(90195, 91455, 91456, 91457, 91458);
  script_xref(name:"EDB-ID", value:"24494");
  script_xref(name:"IAVA", value:"2013-A-0073");

  script_name(english:"Polycom HDX < 3.1.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Polycom HDX.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the firmware installed
on the remote host is affected by multiple vulnerabilities :

  - A command shell authorization bypass vulnerability
    exists that could be used by a malicious user to gain
    unauthorized access to the system, which could result
    in information disclosure.

  - A command injection vulnerability exists that could
    allow an authenticated, malicious user to execute
    arbitrary commands on the system when using the
    firmware update functionality.

  - A privilege escalation vulnerability exists that could
    lead to unauthorized system access and information
    disclosure.

  - An H.323 format string vulnerability exists via a
    maliciously crafted call setup message that could lead
    to system instability or remote code execution.

  - A SQL injection vulnerability exists via a maliciously
    crafted call setup message that could lead to remote
    code execution.

  - The Polycom HDX uses a software update process that
    reads a PUP file containing all of the information and
    tools needed to properly update the system. A
    vulnerability has been discovered in the PUP file header
    MAC signature verification process that could allow a
    malicious user to extract the components of the PUP
    file.

Note that Nessus has not tested for the issues but has instead relied
only on the application's self-reported version number.");
  # http://support.polycom.com/global/documents/support/documentation/security_bulletin_102404_15989_fhdx_telnet_vulnerability.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37569803");
  # http://knowledgebase-iframe.polycom.com/kb/knowledgebase/End User/Tech Alerts/Video/15989_fHDX Telnet Vulnerability - Security Bulletin 102404.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89cd66e6");
  # http://knowledgebase-iframe.polycom.com/kb/knowledgebase/End User/Tech Alerts/Video/Security Bulletin 107522 - Firmware Update Command Injection.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08be6b0c");
  # http://knowledgebase-iframe.polycom.com/kb/knowledgebase/End User/Tech Alerts/Video/Security Bulletin 107523 - Command Shell Grants System Level Access.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21e1a2ea");
  # http://knowledgebase-iframe.polycom.com/kb/knowledgebase/End User/Tech Alerts/Video/Security Bulletin 107524 - Format String Vulnerability.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3131f5cd");
  # http://knowledgebase-iframe.polycom.com/kb/knowledgebase/End User/Tech Alerts/Video/Security Bulletin 107525 - CDR Database SQL Injection.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7c3ce18");
  # http://knowledgebase-iframe.polycom.com/kb/knowledgebase/End User/Tech Alerts/Video/Security Bulletin 107526 - Pup File Header.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?056cdac1");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Mar/149");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Mar/98");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Mar/151");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Mar/148");
  script_set_attribute(attribute:"solution", value:"Upgrade the firmware to version 3.1.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:polycom:hdx_system_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("polycom_sip_detect.nasl");
  script_require_keys("sip/polycom/hdx");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb = "sip/polycom/hdx";

pairs = get_kb_list_or_exit(kb);
pairs = make_list(pairs);
if (max_index(pairs) == 0) audit(AUDIT_HOST_NONE, "Polycom HDX SIP services");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln = FALSE;
fix = "3.1.1.2";
re = make_array(1, "_(\d+)");
foreach pair (pairs)
{
  list = split(pair, sep:"/", keep:FALSE);
  key = kb + "/" + pair;
  ver = get_kb_item_or_exit(key + "/version");

  if (ver_compare(ver:ver, fix:fix, regexes:re) < 0)
  {
    vuln = TRUE;
    break;
  }
}

model = get_kb_item_or_exit(key + "/model");
full_ver = get_kb_item_or_exit(key + "/full_version");

if (!vuln)
  exit(0, "The " + model + " is running " + full_ver + " firmware, which is unaffected.");

# Report our findings.
set_kb_item(name:'www/0/SQLInjection', value:TRUE);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Model             : HDX ' + model +
    '\n  Installed version : ' + full_ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}
security_hole(port:0, extra:report);
