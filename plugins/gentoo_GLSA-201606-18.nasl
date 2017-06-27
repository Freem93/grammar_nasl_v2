#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201606-18.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(91863);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/02/01 15:04:46 $");

  script_cve_id("CVE-2016-0636", "CVE-2016-0686", "CVE-2016-0687", "CVE-2016-0695", "CVE-2016-3422", "CVE-2016-3425", "CVE-2016-3427", "CVE-2016-3443", "CVE-2016-3449");
  script_xref(name:"GLSA", value:"201606-18");

  script_name(english:"GLSA-201606-18 : IcedTea: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201606-18
(IcedTea: Multiple vulnerabilities)

    Various OpenJDK attack vectors in IcedTea, such as 2D, Corba, Hotspot,
      Libraries, and JAXP, exist which allows remote attackers to affect the
      confidentiality, integrity, and availability of vulnerable systems.  Many
      of the vulnerabilities can only be exploited through sandboxed Java Web
      Start applications and java applets. Please review the CVE identifiers
      referenced below for details.
  
Impact :

    Remote attackers may execute arbitrary code, compromise information, or
      cause Denial of Service.
  
Workaround :

    There is no known work around at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201606-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Gentoo Security is no longer supporting dev-java/icedtea, as it has been
      officially dropped from the stable tree.
    Users of the IcedTea 3.x binary package should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-bin-3.0.1'
    Users of the IcedTea 7.x binary package should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-7.2.6.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:icedtea-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/icedtea-bin", unaffected:make_list("ge 7.2.6.6-r1", "ge 3.0.1"), vulnerable:make_list("lt 7.2.6.6-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IcedTea");
}
