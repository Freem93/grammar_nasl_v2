#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201309-24.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(70184);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 14:27:07 $");

  script_cve_id("CVE-2011-2901", "CVE-2011-3262", "CVE-2012-0217", "CVE-2012-0218", "CVE-2012-2934", "CVE-2012-3432", "CVE-2012-3433", "CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3497", "CVE-2012-3498", "CVE-2012-3515", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5512", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515", "CVE-2012-5525", "CVE-2012-5634", "CVE-2012-6030", "CVE-2012-6031", "CVE-2012-6032", "CVE-2012-6033", "CVE-2012-6034", "CVE-2012-6035", "CVE-2012-6036", "CVE-2012-6075", "CVE-2012-6333", "CVE-2013-0151", "CVE-2013-0152", "CVE-2013-0153", "CVE-2013-0154", "CVE-2013-0215", "CVE-2013-1432", "CVE-2013-1917", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-1920", "CVE-2013-1922", "CVE-2013-1952", "CVE-2013-1964", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2211");
  script_bugtraq_id(49370, 53856, 53955, 53961, 54691, 54942, 55400, 55406, 55410, 55412, 55413, 55414, 55442, 56498, 56794, 56796, 56797, 56798, 56799, 56803, 56805, 57159, 57223, 57420, 57494, 57495, 57742, 57745, 58880, 59070, 59291, 59292, 59293, 59615, 59617, 60277, 60278, 60282, 60701, 60702, 60703, 60721, 60799);
  script_osvdb_id(73740, 74873, 82850, 82933, 82934, 82943, 82949, 83072, 84241, 84514, 85196, 85197, 85198, 85199, 85200, 85202, 85203, 86676, 86677, 86678, 87297, 87298, 87305, 87306, 87307, 88127, 88128, 88129, 88130, 88131, 88132, 88133, 88655, 88913, 89058, 89319, 89471, 89472, 89853, 89867, 92050, 92492, 92563, 92564, 92565, 92983, 92984, 93820, 93821, 93822, 94077, 94442, 94443, 94464, 94600);
  script_xref(name:"GLSA", value:"201309-24");

  script_name(english:"GLSA-201309-24 : Xen: Multiple vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-201309-24
(Xen: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Xen. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    Guest domains could possibly gain privileges, execute arbitrary code, or
      cause a Denial of Service on the host domain (Dom0). Additionally, guest
      domains could gain information about other virtual machines running on
      the same host or read arbitrary files on the host.
  
Workaround :

    The CVEs listed below do not currently have fixes, but only apply to Xen
      setups which have &ldquo;tmem&rdquo; specified on the hypervisor command line.
      TMEM is not currently supported for use in production systems, and
      administrators using tmem should disable it.
      Relevant CVEs:
      * CVE-2012-2497
      * CVE-2012-6030
      * CVE-2012-6031
      * CVE-2012-6032
      * CVE-2012-6033
      * CVE-2012-6034
      * CVE-2012-6035
      * CVE-2012-6036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-09/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201309-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Xen users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-4.2.2-r1'
    All Xen-tools users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/xen-tools-4.2.2-r3'
    All Xen-pvgrub users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/xen-pvgrub-4.2.2-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-pvgrub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"app-emulation/xen", unaffected:make_list("ge 4.2.2-r1"), vulnerable:make_list("lt 4.2.2-r1"))) flag++;
if (qpkg_check(package:"app-emulation/xen-pvgrub", unaffected:make_list("ge 4.2.2-r1"), vulnerable:make_list("lt 4.2.2-r1"))) flag++;
if (qpkg_check(package:"app-emulation/xen-tools", unaffected:make_list("ge 4.2.2-r3"), vulnerable:make_list("lt 4.2.2-r3"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
