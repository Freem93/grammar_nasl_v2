#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201504-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(82734);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/17 13:32:19 $");

  script_cve_id("CVE-2013-2212", "CVE-2013-3495", "CVE-2014-3967", "CVE-2014-3968", "CVE-2014-5146", "CVE-2014-5149", "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9030", "CVE-2014-9065", "CVE-2014-9066", "CVE-2015-0361", "CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2152", "CVE-2015-2751", "CVE-2015-2752", "CVE-2015-2756");
  script_bugtraq_id(61424, 61854, 67794, 67824, 69198, 69199, 71149, 71151, 71207, 71331, 71332, 71544, 71546, 71882, 72577, 72954, 72955, 73068, 73443, 73448);
  script_xref(name:"GLSA", value:"201504-04");

  script_name(english:"GLSA-201504-04 : Xen: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201504-04
(Xen: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Xen.  Please review the
      CVE identifiers referenced below for details.
  
Impact :

    A local attacker could possibly cause a Denial of Service condition or
      obtain sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201504-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Xen 4.4 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-4.4.2-r1'
    All Xen 4.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-emulation/xen-4.2.5-r8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-emulation/xen", unaffected:make_list("ge 4.4.2-r1", "rge 4.2.5-r8"), vulnerable:make_list("lt 4.4.2-r1"))) flag++;

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
