#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70884);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id(
    "CVE-2010-4008",
    "CVE-2011-0216",
    "CVE-2011-1944",
    "CVE-2011-2834",
    "CVE-2011-3905",
    "CVE-2011-3919",
    "CVE-2012-0841"
  );
  script_bugtraq_id(44779, 48056, 48832, 49658, 51084, 51300, 52107);
  script_osvdb_id(69205, 73248, 73994, 75560, 77707, 78148, 79437);
  script_xref(name:"VMSA", value:"2012-0012");

  script_name(english:"ESXi 5.0 < Build 764879 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks ESXi version and build number");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is affected by the following security
vulnerabilities :

  - Errors exist in the Libxml2 library functions
    'xmlXPathNextPrecedingSibling', 'xmlNodePtr' and
    'xmlXPathNextPrecedingInternal' that could allow
    denial of service attacks or arbitrary code execution.
    (CVE-2010-4008)

  - Buffer overflow errors exist in the libxml2 library
    functions 'xmlCharEncFirstLineInt' and
    'xmlCharEncInFunc' that could allow denial of service
    attacks or arbitrary code execution. (CVE-2011-0216)

  - A buffer overflow error exists in the libxml2 library
    file 'xpath.c' related to handling 'XPath' nodesets that
    could allow denial of service attacks or arbitrary code
    execution. (CVE-2011-1944)

  - A double-free error exists in the libxml2 library
    function 'xmlXPathCompOpEval' related to handling
    invalid 'XPath' expressions that could allow denial of
    service attacks or arbitrary code execution.
    (CVE-2011-2834)

  - An out-of-bounds read error exists in the libxml2
    library file 'parser.c' related to handling 'Stop'
    orders that could allow denial of service attacks.
    (CVE-2011-3905)

  - A buffer overflow error exists in the libxml2 library
    function 'xmlStringLenDecodeEntities' related to
    copying entities that could allow denial of service
    attacks or arbitrary code execution. (CVE-2011-3919)

  - An error exists in the libxml2 library related to hash
    collisions that could allow denial of service attacks.
    (CVE-2012-0841)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2020572");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0012.html");
  script_set_attribute(attribute:"solution", value:"Apply patch ESXi500-201207101-SG.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/12");
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
fixed_build = 764879;

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
