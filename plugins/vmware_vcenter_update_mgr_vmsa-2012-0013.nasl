#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66909);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id(
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1717",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1720",
    "CVE-2012-1723",
    "CVE-2012-1725"
  );
  script_bugtraq_id(
    53946,
    53947,
    53949,
    53950,
    53951,
    53952,
    53954,
    53956,
    53960
  );
  script_osvdb_id(
    82874,
    82877,
    82878,
    82879,
    82880,
    82882,
    82884,
    82885,
    82886
  );
  script_xref(name:"VMSA", value:"2012-0013");
  script_xref(name:"IAVA", value:"2012-A-0146");

  script_name(english:"VMware vCenter Update Manager Multiple Vulnerabilities (VMSA-2012-0013)");
  script_summary(english:"Checks the version of Update Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an update manager installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Update Manager installed on the remote
Windows host is 4.0 earlier than Update 4a, or 4.1 earlier than Update
3.  Such versions use a version of the Oracle JRE 1.5 that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0013.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000197.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vCenter Update Manager 4.0 Update 4a / 4.1 Update 3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_update_mgr_installed.nasl");
  script_require_keys("SMB/VMware vCenter Update Manager/Version", "SMB/VMware vCenter Update Manager/Build", "SMB/VMware vCenter Update Manager/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'VMware vCenter Update Manager';
version = get_kb_item_or_exit("SMB/" + app + "/Version");
build = get_kb_item_or_exit("SMB/" + app + "/Build");
path = get_kb_item_or_exit("SMB/" + app + "/Path");

fix = '';
if (version =~ '^4\\.0\\.' && int(build) < 817876)
{
  fix = '4.0.0 build 817876';
}
else if (version =~ '^4\\.1\\.' && int(build) < 816769)
{
  fix = '4.1.0 build 816769';
}

if (fix)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' build ' + build +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, app, version + ' build ' + build, path);
