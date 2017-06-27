#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79215);
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
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"MCAFEE-SB", value:"SB10085");

  script_name(english:"McAfee Web Gateway GNU Bash Code Injection (SB10085) (Shellshock)");
  script_summary(english:"Checks the version of McAfee Web Gateway.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a code injection vulnerability known as
Shellshock.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Web Gateway (MWG) installed
that is affected by a command injection vulnerability in GNU Bash
known as Shellshock. The vulnerability is due to the processing of
trailing strings after function definitions in the values of
environment variables. This allows a remote attacker to execute
arbitrary code via environment variable manipulation depending on the
configuration of the system.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10085");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB83022");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:web_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("mcafee_web_gateway_detect.nbin");
  script_require_keys("Host/McAfee Web Gateway/Version", "Host/McAfee Web Gateway/Display Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "McAfee Web Gateway";
version = get_kb_item_or_exit("Host/McAfee Web Gateway/Version");
version_display = get_kb_item_or_exit("Host/McAfee Web Gateway/Display Version");

fix = FALSE;

if (
  version =~ "^6\." ||
  version =~ "^7\.[0-4]\."
)
{
  fix_display = "7.4.2.3 Build 18233 / 7.5.0";
  fix = "7.4.2.3.0.18233";
}

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version_display +
      '\n  Fixed version     : ' + fix_display +
      '\n';
      security_hole(extra:report, port:0);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version_display);
