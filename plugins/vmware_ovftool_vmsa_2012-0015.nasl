#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63075);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/10 13:19:30 $");

  script_cve_id("CVE-2012-3569");
  script_bugtraq_id(56468);
  script_osvdb_id(87117);
  script_xref(name:"VMSA", value:"2012-0015");

  script_name(english:"VMware OVF Tool 2.1 File Handling Format String Vulnerability (VMSA-2012-0015)");
  script_summary(english:"Checks version of OVF Tool");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a tool installed that is affected by a
format string vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the VMware OVF Tool installed on the remote Windows host
is potentially affected by a format string vulnerability.  By tricking a
user into loading a specially crafted OVF file a remote, unauthenticated
attacker could execute arbitrary code on the remote host subject to the
privileges of the user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0015.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000193.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware OVF Tool 3.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMWare OVF Tools Format String Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:ovf_tool");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_ovftool_installed.nasl");
  script_require_keys("SMB/VMware OVF Tool/Path", "SMB/VMware OVF Tool/Version");
  
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/VMware OVF Tool/Version");
path = get_kb_item_or_exit("SMB/VMware OVF Tool/Path");

if (version !~ '^2\\.1') exit(0, "The VMware OVF Tool install under "+path+" is "+version+", not 2.1.");

fixed_version = '3.0.1';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware OVF Tool', version);
