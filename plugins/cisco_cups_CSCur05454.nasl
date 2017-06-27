#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79124);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/04/25 20:29:04 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-6277",
    "CVE-2014-6278",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187"
  );
  script_bugtraq_id(70103, 70137, 70152, 70154, 70165, 70166);
  script_osvdb_id(112004, 112096, 112097, 112158, 112169);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur05454");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140926-bash");
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"CUCM IM and Presence Service GNU Bash Environment Variable Handling Command Injection (CSCur05454) (Shellshock)");
  script_summary(english:"Checks the CUPS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the CUCM IM and Presence
Service installed on the remote host contains a version of GNU Bash
that is affected by a command injection vulnerability known as
Shellshock, which is due to the processing of trailing strings after
function definitions in the values of environment variables. This
allows a remote attacker to execute arbitrary code via environment
variable manipulation depending on the configuration of the system.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur05454");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Unified Presence Server 10.5(1.12900.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "cisco_unified_detect.nasl");
  script_require_ports("Host/UCOS/Cisco Unified Presence/version", "cisco_cups/system_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Leverage API version first
display_version = get_kb_item("cisco_cups/system_version");
# Fall back to SSH
if (isnull(display_version))
{
  display_version = get_kb_item_or_exit('Host/UCOS/Cisco Unified Presence/version');
  match = eregmatch(string:display_version, pattern:'^([0-9.]+(?:-[0-9]+)?)($|[^0-9])');
  if (isnull(match)) audit(AUDIT_FN_FAIL, 'eregmatch');
  version = match[1];
}
else version = display_version;

version = str_replace(string:version, find:"-", replace:".");
fix = "10.5.1.12900.2";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_version +
      '\n  Fixed version     : 10.5.1.12900-2' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'CUCM IM and Presence Service', display_version);
