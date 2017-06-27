#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78508);
  script_version("$Revision: 1.15 $");
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
  script_xref(name:"VMSA", value:"2014-0010");

  script_name(english:"VMware vCenter Server Appliance Bash Remote Code Execution (VMSA-2014-0010) (Shellshock)");
  script_summary(english:"Checks the version of VMware vCenter Server Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server Appliance installed on the remote
host is 5.0 prior to Update 3b, 5.1 prior to Update 2b, or 5.5 prior
to Update 2a. It therefore contains a version of bash that is affected
by a command injection vulnerability via environment variable
manipulation. Depending on the configuration of the system, an
attacker could remotely execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0010.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server Appliance 5.0 Update 3b / 5.1 Update
2b / 5.5 Update 2a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server_appliance");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Server Appliance/Version", "Host/VMware vCenter Server Appliance/Build");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vCenter Server Appliance/Version");
build = get_kb_item_or_exit("Host/VMware vCenter Server Appliance/Build");

if (version == "5.0.0")
{
  fixed_main_ver = "5.0.0";
  fixed_build = 2170782;
}
else if (version == "5.1.0")
{
  fixed_main_ver = "5.1.0";
  fixed_build = 2170517;
}
else if (version == "5.5.0")
{
  fixed_main_ver = "5.5.0";
  fixed_build = 2170515;
}
else audit(AUDIT_NOT_INST, "VMware vCenter Server Appliance 5.0.x / 5.1.x / 5.5.x");

if (int(build) < fixed_build)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : ' + fixed_main_ver + ' Build ' + fixed_build + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCenter Server Appliance', version + ' Build ' + build);
