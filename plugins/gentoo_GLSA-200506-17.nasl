#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200506-17.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18538);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1266", "CVE-2005-2024");
  script_osvdb_id(17346, 17390, 17391);
  script_xref(name:"GLSA", value:"200506-17");

  script_name(english:"GLSA-200506-17 : SpamAssassin 3, Vipul's Razor: Denial of Service vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200506-17
(SpamAssassin 3, Vipul's Razor: Denial of Service vulnerability)

    SpamAssassin and Vipul's Razor contain a Denial of Service
    vulnerability when handling special misformatted long message headers.
  
Impact :

    By sending a specially crafted message an attacker could cause a Denial
    of Service attack against the SpamAssassin/Vipul's Razor server.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://mail-archives.apache.org/mod_mbox/spamassassin-announce/200506.mbox/%3c17072.35054.586017.822288@proton.pathname.com%3e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19eed3bf"
  );
  # http://sourceforge.net/mailarchive/forum.php?thread_id=7520323&forum_id=4259
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?883b0199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200506-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SpamAssassin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-filter/spamassassin-3.0.4'
    All Vipul's Razor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-filter/razor-2.74'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:razor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-filter/spamassassin", unaffected:make_list("ge 3.0.4", "lt 3.0.1"), vulnerable:make_list("lt 3.0.4"))) flag++;
if (qpkg_check(package:"mail-filter/razor", unaffected:make_list("ge 2.74"), vulnerable:make_list("lt 2.74"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SpamAssassin 3 / Vipul's Razor");
}
