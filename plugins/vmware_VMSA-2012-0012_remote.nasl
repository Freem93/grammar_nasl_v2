#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89037);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/01 14:49:47 $");

  script_cve_id(
    "CVE-2010-4008",
    "CVE-2011-0216",
    "CVE-2011-1944",
    "CVE-2011-2834",
    "CVE-2011-3905",
    "CVE-2011-3919",
    "CVE-2012-0841"
  );
  script_bugtraq_id(
    44779,
    48056,
    48832,
    49658, 
    51084,
    51300,
    52107
  );
  script_osvdb_id(
    69205,
    73248,
    73994,
    75560,
    77707,
    78148,
    79437
  );
  script_xref(name:"VMSA", value:"2012-0012");

  script_name(english:"VMware ESX / ESXi libxml2 Multiple Vulnerabilities (VMSA-2012-0012) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is affected by multiple
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    the bundled libxml2 library in the
    xmlXPathNextPrecedingSibling(), xmlNodePtr(), and
    xmlXPathNextPrecedingInternal() functions due to
    improper processing of namespaces and attributes nodes.
    A remote attacker can exploit these, via a specially
    crafted XML file, to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2010-4008)

  - Multiple remote code execution vulnerabilities exist in
    the bundled libxml2 library in the
    xmlCharEncFirstLineInt() and xmlCharEncInFunc()
    functions due to an off-by-one overflow condition. A
    remote attacker can exploit these, via a specially
    crafted XML file, to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2011-0216)

  - A remote code execution vulnerability exists in the
    bundled libxml2 library due to improper sanitization of
    user-supplied input when processing an XPath nodeset. A
    remote attacker can exploit this, via a specially
    crafted request, to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2011-1944)

  - A remote code execution vulnerability exists in the
    bundled libxml2 library in the xmlXPathCompOpEval()
    function due to improper processing of invalid XPath
    expressions. A remote attacker can exploit this, via a
    specially crafted XSLT stylesheet, to cause a denial of
    service condition or the execution of arbitrary code. 
    (CVE-2011-2834)

  - A denial of service vulnerability exists in the bundled
    libxml2 library due to multiple out-of-bounds read
    errors in parser.c that occur when getting a Stop order.
    A remote attacker can exploit this, via a specially
    crafted XML document, to cause a denial of service
    condition. (CVE-2011-3905)

  - A remote code execution vulnerability exists in the
    bundled libxml2 library in the
    xmlStringLenDecodeEntities() function in parser.c due
    to an overflow condition that occurs when copying
    entities. A remote attacker can exploit this, via a
    specially crafted request, to cause a heap-based buffer
    overflow, resulting in a denial of service condition or
    the execution of arbitrary code. (CVE-2011-3919)

  - A denial of service vulnerability exists in the bundled
    libxml2 library due to improper processing of crafted
    parameters. A remote attacker can exploit this to cause
    a hash collision, resulting in a denial of service
    condition. (CVE-2012-0841)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0012.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 5.0 or ESXi version 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");
port    = get_kb_item_or_exit("Host/VMware/vsphere");

# Version + build map
# https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1014508
fixes = make_array();
fixes["ESXi 4.0"] = 787047;
fixes["ESXi 4.1"] = 800380;
fixes["ESXi 5.0"] = 764879;

# Extra fixes to report
extra_fixes = make_array();
extra_fixes["ESXi 4.1"] = 811144;
extra_fixes["ESXi 5.0"] = 768111;

matches = eregmatch(pattern:'^VMware (ESXi?).*build-([0-9]+)$', string:release);
if (empty_or_null(matches))
  exit(1, 'Failed to extract the ESX / ESXi build number.');

type  = matches[1];
if (type == "ESX") audit(AUDIT_HOST_NOT, "VMware ESXi");

build = int(matches[2]);

fixed_build = fixes[version];

if (!isnull(fixed_build) && build < fixed_build)
{
  if (!empty_or_null(extra_fixes[version])) fixed_build += " / " + extra_fixes[version];

  report = '\n  ESXi version    : ' + version +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
