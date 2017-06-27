#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78771);
  script_version("$Revision: 1.14 $");
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
  script_xref(name:"EDB-ID", value:"34860");
  script_xref(name:"VMSA", value:"2014-0010");

  script_name(english:"VMware vSphere Replication Bash Environment Variable Command Injection Vulnerability (VMSA-2014-0010) (Shellshock)");
  script_summary(english:"Checks the version of vSphere Replication.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by Shellshock.");
  script_set_attribute(attribute:"description", value:
"The VMware vSphere Replication installed on the remote host is version
5.1.x prior to 5.1.2.2, 5.5.x prior to 5.5.1.3, 5.6.x prior to
5.6.0.2, or 5.8.x prior to 5.8.0.1. It is, therefore, affected by a
command injection vulnerability in GNU Bash known as Shellshock, which
is due to the processing of trailing strings after function
definitions in the values of environment variables. This allows a
remote attacker to execute arbitrary code via environment variable
manipulation depending on the configuration of the system");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0010");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vSphere Replication 5.1.2.2 / 5.5.1.3 / 5.6.0.2 / 5.8.0.1
or later.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vsphere_replication");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vSphere Replication/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vSphere Replication/Version");
verui = get_kb_item_or_exit("Host/VMware vSphere Replication/VerUI");
build = get_kb_item_or_exit("Host/VMware vSphere Replication/Build");

fix = '';

if (version =~ '^5\\.1\\.' && int(build) < 2170306) fix = '5.1.2 Build 2170306';
else if (version =~ '^5\\.5\\.' && int(build) < 2170307) fix = '5.5.1 Build 2170307';
else if (version =~ '^5\\.6\\.' && int(build) < 2172161) fix = '5.6.0 Build 2172161';
else if (version =~ '^5\\.8\\.' && int(build) < 2170514) fix = '5.8.0 Build 2170514';

if (!empty(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + verui +
      '\n  Fixed version     : ' + fix + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vSphere Replication', verui);
