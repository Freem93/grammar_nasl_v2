#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79584);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

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
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur02103");
  script_xref(name:"CISCO-SA",value:"cisco-sa-20140926-bash");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"Cisco TelePresence Conductor Bash Remote Code Execution (Shellshock)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco TelePresence Conductor device is affected by a
command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, remote Cisco
TelePresence Conductor device is affected by a command injection
vulnerability in GNU Bash known as Shellshock. The vulnerability is
due to the processing of trailing strings after function definitions
in the values of environment variables. This allows a remote attacker
to execute arbitrary code via environment variable manipulation
depending on the configuration of the system.

Note that an attacker must be authenticated before the device is
exposed to this exploit.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur02103");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7269978d");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.3.1 / 2.4.1 / 3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_conductor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_conductor_detect.nbin");
  script_require_keys("Host/Cisco_TelePresence_Conductor/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

prod = "Cisco TelePresence Conductor";
version = get_kb_item_or_exit("Host/Cisco_TelePresence_Conductor/Version");

if (
  version =~ "^1(\.|$)" ||
  (version =~ "^2\.(0|1|2)(\.|$)") ||
  (version =~ "^2\.3(\.|$)" && ver_compare(ver:version, fix:"2.3.1", strict:FALSE) < 0) ||
  (version =~ "^2\.4(\.|$)" && ver_compare(ver:version, fix:"2.4.1", strict:FALSE) < 0)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed versions    : 2.3.1 / 2.4.1 / 3.0' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, prod, version);
