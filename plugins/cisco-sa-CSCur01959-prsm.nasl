#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78828);
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
  script_xref(name:"CISCO-BUG-ID", value:"CSCur01959");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140926-bash");
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"Cisco Prime Security Manager GNU Bash Environment Variable Handling Command Injection (cisco-sa-20140926-bash) (Shellshock)");
  script_summary(english:"Checks the PRSM version.");

  script_set_attribute(attribute:"synopsis", value:
"The management application installed on the remote host is affected by
a command injection vulnerability known as Shellshock.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
Prime Security Manager installed on the remote host is affected by a
command injection vulnerability in GNU Bash known as Shellshock. The
vulnerability is due to the processing of trailing strings after
function definitions in the values of environment variables. This
allows a remote attacker to execute arbitrary code via environment
variable manipulation depending on the configuration of the system.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7269978d");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Prime Security Manager 9.3.2.1 (9) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_security_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_prsm_web_detect.nasl");
  script_require_keys("installed_sw/Cisco PRSM");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("http_func.inc");
include("install_func.inc");
include("cisco_func.inc");

app = 'Cisco PRSM';

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
base_url = build_url(qs:install['path'], port:port);
ver = install['version'];

fix = '9.3.2.1 (9)';

# Versions 9.1.x, 9.2.x, and 9.3.x blow 9.3.2.1 (9) are vulnerable
if (
  cisco_gen_ver_compare(a:ver, b:"9.1.0") >= 0 &&
  cisco_gen_ver_compare(a:ver, b:fix) < 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + base_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, base_url, ver);
