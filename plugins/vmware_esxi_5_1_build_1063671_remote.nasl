#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70886);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id(
    "CVE-2009-5029",
    "CVE-2009-5064",
    "CVE-2010-0830",
    "CVE-2011-1089",
    "CVE-2011-1202",
    "CVE-2011-3102",
    "CVE-2011-3970",
    "CVE-2011-4609",
    "CVE-2012-0864",
    "CVE-2012-2807",
    "CVE-2012-2825",
    "CVE-2012-2870",
    "CVE-2012-2871",
    "CVE-2012-3404",
    "CVE-2012-3405",
    "CVE-2012-3406",
    "CVE-2012-3480",
    "CVE-2012-5134",
    "CVE-2013-5973"
  );
  script_bugtraq_id(
    40063,
    46740,
    47668,
    50898,
    51439,
    51911,
    52201,
    53540,
    54203,
    54374,
    54718,
    54982,
    55331,
    56684,
    64075,
    64491
  );
  script_osvdb_id(
    65077,
    72490,
    74278,
    74883,
    77508,
    78316,
    78950,
    79705,
    80719,
    81964,
    83255,
    83266,
    84710,
    85035,
    85036,
    87882,
    88150,
    88151,
    88152,
    91608,
    101387
  );
  script_xref(name:"VMSA", value:"2012-0018");
  script_xref(name:"VMSA", value:"2013-0004");
  script_xref(name:"VMSA", value:"2013-0001");

  script_name(english:"ESXi 5.1 < Build 1063671 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.1 host is affected by multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.1 host is affected by the following security
vulnerabilities :

  - An integer overflow condition exists in the glibc
    library in the __tzfile_read() function that allows a
    denial of service or arbitrary code execution.
    (CVE-2009-5029)

  - An error exists in the glibc library related to modified
    loaders and 'LD_TRACE_LOADED_OBJECTS' checks that allow
    arbitrary code execution. This issue is disputed by the
    creators of glibc. (CVE-2009-5064)

  - An integer signedness error exists in the
    elf_get_dynamic_info() function in elf/dynamic-link.h
    that allows arbitrary code execution. (CVE-2010-0830)

  - An error exists in the glibc library in the addmntent()
    function that allows a corruption of the '/etc/mtab'
    file. (CVE-2011-1089)

  - An error exists in the libxslt library in the
    xsltGenerateIdFunction() function that allows the
    disclosure of sensitive information. (CVE-2011-1202)

  - An off-by-one overflow condition exists in the
    xmlXPtrEvalXPtrPart() function due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted XML file, to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2011-3102)

  - An out-of-bounds read error exists in the libxslt
    library in the xsltCompilePatternInternal() function
    that allows a denial of service. (CVE-2011-3970)

  - An error exists in the glibc library in the svc_run()
    function that allows a denial of service.
    (CVE-2011-4609)

  - An overflow error exists in the glibc library in the
    printf() function related to 'nargs' parsing that allows
    arbitrary code execution. (CVE-2012-0864)

  - Multiple integer overflow conditions exist due to
    improper validation of user-supplied input when handling
    overly long strings. An unauthenticated, remote
    attacker can exploit this, via a specially crafted XML
    file, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2012-2807)

  - Multiple type-confusion errors exist in the 
    'IS_XSLT_ELEM' macro and the xsltApplyTemplates()
    function that allow a denial of service or the
    disclosure of sensitive information. (CVE-2012-2825,
    CVE-2012-2871)

  - A use-after-free error exists in the libxslt library in
    the xsltGenerateIdFunction() function that allows a
    denial of service or arbitrary code execution.
    (CVE-2012-2870)

  - Multiple format string error exist in glibc that allow
    arbitrary code execution. (CVE-2012-3404, CVE-2012-3405,
    CVE-2012-3406)

  - Multiple overflow errors exist in the glibc functions
    strtod(), strtof(), strtold(), and strtod_l() that allow
    arbitrary code execution. (CVE-2012-3480)

  - A heap-based underflow condition exists in the bundled
    libxml2 library due to incorrect parsing of strings not
    containing an expected space. A remote attacker can
    exploit this, via a specially crafted XML document, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2012-5134)

  - An arbitrary file modification vulnerability due to
    improper handling of certain Virtual Machine file
    descriptors. A local attacker can exploit this to read
    or modify arbitrary files. (CVE-2013-5973)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2041637");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0018.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0014.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0004.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0001.html");
  script_set_attribute(attribute:"solution", value:"Apply patch ESXi510-201304101-SG.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
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
fixed_build = 1063671;

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
