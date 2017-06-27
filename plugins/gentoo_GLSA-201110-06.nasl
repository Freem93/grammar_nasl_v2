#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201110-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56459);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/27 16:45:02 $");

  script_cve_id("CVE-2006-7243", "CVE-2009-5016", "CVE-2010-1128", "CVE-2010-1129", "CVE-2010-1130", "CVE-2010-1860", "CVE-2010-1861", "CVE-2010-1862", "CVE-2010-1864", "CVE-2010-1866", "CVE-2010-1868", "CVE-2010-1914", "CVE-2010-1915", "CVE-2010-1917", "CVE-2010-2093", "CVE-2010-2094", "CVE-2010-2097", "CVE-2010-2100", "CVE-2010-2101", "CVE-2010-2190", "CVE-2010-2191", "CVE-2010-2225", "CVE-2010-2484", "CVE-2010-2531", "CVE-2010-2950", "CVE-2010-3062", "CVE-2010-3063", "CVE-2010-3064", "CVE-2010-3065", "CVE-2010-3436", "CVE-2010-3709", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4150", "CVE-2010-4409", "CVE-2010-4645", "CVE-2010-4697", "CVE-2010-4698", "CVE-2010-4699", "CVE-2010-4700", "CVE-2011-0420", "CVE-2011-0421", "CVE-2011-0708", "CVE-2011-0752", "CVE-2011-0753", "CVE-2011-0755", "CVE-2011-1092", "CVE-2011-1148", "CVE-2011-1153", "CVE-2011-1464", "CVE-2011-1466", "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470", "CVE-2011-1471", "CVE-2011-1657", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483", "CVE-2011-3182", "CVE-2011-3189", "CVE-2011-3267", "CVE-2011-3268");
  script_osvdb_id(62582, 62583, 63323, 64322, 64526, 64527, 64544, 64545, 64546, 64607, 64608, 64662, 64663, 64664, 65055, 65755, 66086, 66087, 66093, 66094, 66095, 66096, 66097, 66098, 66099, 66100, 66101, 66102, 66103, 66104, 66105, 66106, 66798, 66804, 66805, 67418, 67419, 67420, 67421, 68597, 69109, 69110, 69227, 69230, 69651, 69660, 70370, 70606, 70607, 70608, 70609, 70610, 71597, 71598, 72531, 72532, 72533, 72644, 73113, 73218, 73275, 73622, 73623, 73624, 73625, 73626, 73754, 73755, 74193, 74688, 74726, 74728, 74738, 74739, 74742, 74743, 75200);
  script_xref(name:"GLSA", value:"201110-06");

  script_name(english:"GLSA-201110-06 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201110-06
(PHP: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in PHP. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A context-dependent attacker could execute arbitrary code, obtain
      sensitive information from process memory, bypass intended access
      restrictions, or cause a Denial of Service in various ways.
    A remote attacker could cause a Denial of Service in various ways,
      bypass spam detections, or bypass open_basedir restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201110-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/php-5.3.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/php", unaffected:make_list("ge 5.3.8"), vulnerable:make_list("lt 5.3.8"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
