#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200408-23.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14579);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_osvdb_id(9117);
  script_xref(name:"GLSA", value:"200408-23");

  script_name(english:"GLSA-200408-23 : kdelibs: Cross-domain cookie injection vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200408-23
(kdelibs: Cross-domain cookie injection vulnerability)

    kcookiejar contains a vulnerability which may allow a malicious website to
    set cookies for other websites under the same second-level domain.
    This vulnerability applies to country-specific secondary top level domains
    that use more than 2 characters in the secondary part of the domain name,
    and that use a secondary part other than com, net, mil, org, gov, edu or
    int. However, certain popular domains, such as co.uk, are not affected.
  
Impact :

    Users visiting a malicious website using the Konqueror browser may have a
    session cookie set for them by that site. Later, when the user visits
    another website under the same domain, the attacker's session cookie will
    be used instead of the cookie issued by the legitimate site. Depending on
    the design of the legitimate site, this may allow an attacker to gain
    access to the user's session. For further explanation on this type of
    attack, see the paper titled 'Session Fixation Vulnerability in
    Web-based Applications' (reference 2).
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of kdelibs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20040823-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.acros.si/papers/session_fixation.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200408-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All kdelibs users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=kde-base/kdelibs-3.2.3-r2'
    # emerge '>=kde-base/kdelibs-3.2.3-r2'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"kde-base/kdelibs", unaffected:make_list("ge 3.2.3-r2"), vulnerable:make_list("le 3.2.3-r1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs");
}
