#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80196);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-6277",
    "CVE-2014-6278",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187"
  );
  script_bugtraq_id(
    70103,
    70137,
    70152,
    70154,
    70165,
    70166
  );
  script_osvdb_id(
    112004,
    112096,
    112097,
    112158,
    112169
  );
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"Juniper Junos Space GNU Bash Command Injection Vulnerability (JSA10648) (Shellshock)");
  script_summary(english:"Checks version and bash version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 14.1R2, and may be affected by a command injection
vulnerability in GNU Bash known as Shellshock. The vulnerability is
due to the processing of trailing strings after function definitions
in the values of environment variables. This allows a remote attacker
to execute arbitrary code via environment variable manipulation
depending on the configuration of the system.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10648");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  # http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e40f2f5a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space 14.1R2 or later or apply the relevant patch
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'14.1R2', severity:SECURITY_HOLE);
