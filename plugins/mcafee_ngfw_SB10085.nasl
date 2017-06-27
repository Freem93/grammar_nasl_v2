#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79234);
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

  script_name(english:"McAfee Next Generation Firewall GNU Bash Code Injection (SB10085) (Shellshock)");
  script_summary(english:"Checks the NGFW version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a code injection vulnerability known as
Shellshock.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Next Generation Firewall
(NGFW) installed that is affected by a command injection vulnerability
in GNU Bash known as Shellshock. The vulnerability is due to the
processing of trailing strings after function definitions in the
values of environment variables. This allows a remote attacker to
execute arbitrary code via environment variable manipulation depending
on the configuration of the system.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10085");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfix referenced in the vendor advisory.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:ngfw");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_dependencies("mcafee_ngfw_version.nbin");
  script_require_keys("Host/McAfeeNGFW/version");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "McAfee Next Generation Firewall";
version = get_kb_item_or_exit("Host/McAfeeNGFW/version");

# Determine fix.
if (
  version =~ "^[2-4]\." ||
  version =~ "^5\.[0-3]\."
) fix = "5.3.11.9128";
else if (version =~ "^5\.[45]\.") fix = "5.5.11.9904";
else if (version =~ "^5\.7\.") fix = "5.7.5.11048";
else if (version =~ "^5\.8\.") fix = "5.8.0.12042";
else audit(AUDIT_INST_VER_NOT_VULN, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, version);
