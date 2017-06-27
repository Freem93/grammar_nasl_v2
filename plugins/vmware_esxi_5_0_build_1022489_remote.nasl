#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70877);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2011-3102", "CVE-2012-2807", "CVE-2012-5134", "CVE-2013-3519");
  script_bugtraq_id(53540, 54718, 56684, 64075);
  script_osvdb_id(81964, 83266, 87882, 100514);
  script_xref(name:"VMSA", value:"2013-0001");
  script_xref(name:"VMSA", value:"2013-0004");
  script_xref(name:"VMSA", value:"2013-0014");

  script_name(english:"ESXi 5.0 < Build 1022489 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is affected by the following
vulnerabilities :

  - An off-by-one overflow condition exists in the
    xmlXPtrEvalXPtrPart() function due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted XML file, to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2011-3102)

  - Multiple integer overflow conditions exist due to
    improper validation of user-supplied input when handling
    overly long strings. An unauthenticated, remote
    attacker can exploit this, via a specially crafted XML
    file, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2012-2807)

  - A heap-based underflow condition exists in the bundled
    libxml2 library due to incorrect parsing of strings not
    containing an expected space. A remote attacker can
    exploit this, via a specially crafted XML document, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2012-5134)

  - A privilege escalation vulnerability exists due to
    improper handling of control code in the lgtosync.sys
    driver. A local attacker can exploit this escalate
    privileges on Windows-based 32-bit guest operating
    systems. (CVE-2013-3519)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2044378");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0004.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0014.html");
  script_set_attribute(attribute:"solution", value:"Apply patch ESXi500-201303101-SG.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/28");
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
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 1022489;

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
