#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70888);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id("CVE-2011-3048", "CVE-2013-1406", "CVE-2013-1659");
  script_bugtraq_id(52830, 57867, 58115);
  script_osvdb_id(80822, 90019, 90554);
  script_xref(name:"VMSA", value:"2013-0002");
  script_xref(name:"VMSA", value:"2013-0003");

  script_name(english:"ESXi 5.1 < Build 911593 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.1 host is affected by multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.1 host is affected by the following security
vulnerabilities :

  - An input validation error exists in the function
    'png_set_text_2' in the libpng library that could
    allow memory corruption and arbitrary code execution.
    (CVE-2011-3048)

  - A privilege escalation vulnerability exists in the
    Virtual Machine Communication Interface (VMCI). A local
    attacker can exploit this, via control code, to change
    allocated memory, resulting in the escalation of
    privileges. (CVE-2013-1406)

  - An error exists related to Network File Copy (NFC)
    handling that could allow denial of service attacks or
    arbitrary code execution. (CVE-2013-1659)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2035775");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0003.html");
  script_set_attribute(attribute:"solution", value:"Apply ESXi510-201212001-SG.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2013-2016 Tenable Network Security, Inc.");
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
fixed_build = 911593;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host has "+ver+" build "+build+" and thus is not affected.");
