#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70883);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/22 18:36:36 $");

  script_cve_id("CVE-2012-3288", "CVE-2012-3289");
  script_bugtraq_id(53996);
  script_osvdb_id(82979, 82980);
  script_xref(name:"VMSA", value:"2012-0011");

  script_name(english:"ESXi 5.0 < Build 721882 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks ESXi version and build number");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is affected by the following security
vulnerabilities :

  - An error exists related to handling checkpoint files
    that could allow memory corruption leading to arbitrary
    code execution. (CVE-2012-3288)

  - An error exists related to handling mobile device
    traffic data that could lead to denial of service
    conditions. (CVE-2012-3289)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2021031");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0011.html");
  script_set_attribute(attribute:"solution", value:"Apply patch ESXi500-201206401-SG.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

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
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 721882;

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
