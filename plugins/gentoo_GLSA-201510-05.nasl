#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201510-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(86690);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/02 14:33:25 $");

  script_cve_id("CVE-2015-2931", "CVE-2015-2932", "CVE-2015-2933", "CVE-2015-2934", "CVE-2015-2935", "CVE-2015-2936", "CVE-2015-2937", "CVE-2015-2938", "CVE-2015-2939", "CVE-2015-2940", "CVE-2015-2941", "CVE-2015-2942", "CVE-2015-6728", "CVE-2015-6729", "CVE-2015-6730", "CVE-2015-6731", "CVE-2015-6732", "CVE-2015-6733", "CVE-2015-6734", "CVE-2015-6735", "CVE-2015-6736", "CVE-2015-6737");
  script_xref(name:"GLSA", value:"201510-05");

  script_name(english:"GLSA-201510-05 : MediaWiki: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201510-05
(MediaWiki: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MediaWiki. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker may be able to create a Denial of Service condition,
      obtain sensitive information, bypass security restrictions, and inject
      arbitrary web script or HTML.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201510-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MediaWiki 1.25 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.25.2'
    All MediaWiki 1.24 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.24.3'
    All MediaWiki 1.23 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-apps/mediawiki-1.23.10'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");
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

if (qpkg_check(package:"www-apps/mediawiki", unaffected:make_list("ge 1.25.2", "rge 1.24.3", "rge 1.23.10"), vulnerable:make_list("lt 1.25.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MediaWiki");
}
