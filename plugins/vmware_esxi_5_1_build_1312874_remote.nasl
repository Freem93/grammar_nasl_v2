#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71773);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/22 18:36:36 $");

  script_cve_id("CVE-2013-5973");
  script_bugtraq_id(64491);
  script_osvdb_id(101387);
  script_xref(name:"VMSA", value:"2013-0016");

  script_name(english:"ESXi 5.1 < Build 1312873 File Descriptors Privilege Escalation (remote check)");
  script_summary(english:"Checks ESXi version and build number");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.1 host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.1 host is affected by an error in the
handling of certain Virtual Machine file descriptors. This could allow
an unprivileged user with the 'Add Existing Disk' privilege to obtain
read and write access to arbitrary files, possibly leading to
arbitrary code execution after a host reboot.");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2053402");
  script_set_attribute(attribute:"solution", value:"Apply patch ESXi510-201310101-SG.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/31");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.1" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.1");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 1312873;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else exit(0, "The host has "+ver+" build "+build+" and thus is not affected.");
