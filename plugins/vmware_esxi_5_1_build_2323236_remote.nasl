#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79862);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2012-0845",
    "CVE-2012-0876",
    "CVE-2012-1150",
    "CVE-2013-0242",
    "CVE-2013-1752",
    "CVE-2013-1914",
    "CVE-2013-2877",
    "CVE-2013-4238",
    "CVE-2013-4332",
    "CVE-2014-0015",
    "CVE-2014-0138",
    "CVE-2014-0191"
  );
  script_bugtraq_id(
    49778,
    51239,
    51996,
    52379,
    57638,
    58839,
    61050,
    61738,
    62324,
    63804,
    65270,
    66457,
    67233
  );
  script_osvdb_id(
    74829,
    79249,
    80009,
    80892,
    89747,
    92038,
    95032,
    96215,
    97246,
    97247,
    97248,
    101381,
    101382,
    101383,
    101384,
    101385,
    101386,
    102715,
    104972,
    106710
  );
  script_xref(name:"VMSA", value:"2014-0008");
  script_xref(name:"IAVB", value:"2014-B-0161");
  script_xref(name:"VMSA", value:"2014-0012");
  script_xref(name:"CERT", value:"864643");

  script_name(english:"ESXi 5.1 < Build 2323236 Third-Party Libraries Multiple Vulnerabilities (remote check) (BEAST)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.1 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.1 prior to build 2323236. It
is, therefore, affected by the following vulnerabilities in bundled
third-party libraries :

  - Multiple vulnerabilities exist in the bundled Python
    library. (CVE-2011-3389, CVE-2012-0845, CVE-2012-0876,
    CVE-2012-1150, CVE-2013-1752, CVE-2013-4238)

  - Multiple vulnerabilities exist in the bundled GNU C
    Library (glibc). (CVE-2013-0242, CVE-2013-1914,
    CVE-2013-4332)

  - Multiple vulnerabilities exist in the bundled XML
    Parser library (libxml2). (CVE-2013-2877, CVE-2014-0191)

  - Multiple vulnerabilities exist in the bundled cURL
    library (libcurl). (CVE-2014-0015, CVE-2014-0138)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2086288");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0008.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0012.html");
  script_set_attribute(attribute:"solution", value:"Apply patch ESXi510-201412101-SG for ESXi 5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/12");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
fixed_build = 2323236;

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
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
