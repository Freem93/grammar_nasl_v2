#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78770);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-6277",
    "CVE-2014-6278",
    "CVE-2014-7169",
    "CVE-2014-7187"
  );
  script_bugtraq_id(70103, 70137, 70154, 70165, 70166);
  script_osvdb_id(112004, 112097, 112158, 112169);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34860");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur02877");

  script_name(english:"Cisco UCS Director Code Injection (CSCur02877) (Shellshock)");
  script_summary(english:"Checks the Cisco UCS Director version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a vulnerable version of Bash.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote host is running a
version of Cisco UCS Director that could be affected by a command
injection vulnerability in GNU Bash known as Shellshock, which is due
to the processing of trailing strings after function definitions in
the values of environment variables. This allows a remote attacker to
execute arbitrary code via environment variable manipulation depending
on the configuration of the system.

Authentication on the system is required before this vulnerability can
be exploited.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur02877");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID
CSCur02877");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"combined");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ucs_director");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ucs_director_detect.nbin");
  script_require_keys("Host/Cisco/UCSDirector/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

chckver = get_kb_item_or_exit("Host/Cisco/UCSDirector/version");
# Could be unknown version because the WebUI can be detected but
# no version information could be retrieved.
if (chckver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_DEVICE_VER, "Cisco UCS Director");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  (
    ver_compare(ver:chckver, fix:"4.0.0.0", strict:FALSE) >= 0  &&
   ver_compare(ver:chckver, fix:"4.1.0.5", strict:FALSE) <= 0
  ) ||
  (
    ver_compare(ver:chckver, fix:"5.0.0.0", strict:FALSE) >= 0 &&
    ver_compare(ver:chckver, fix:"5.0.0.2", strict:FALSE)  < 0
  )
)
{
  if (report_verbosity > 0)
  {
    if (chckver =~ "^5\.")
      fix = '5.0.0.0 with hotfix cucsd_5_0_0_0_bash_hotfix / 5.0.0.2 / 5.1.0.0';
    else
      fix = '4.1.0.5 with hotfix cucsd_4_1_0_5_bash_hotfix';

    report =
      '\n  Installed version : ' + chckver +
      '\n  Fixed version (s) : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
