#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200801-18.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(30135);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/08/10 14:35:57 $");

  script_osvdb_id(40759, 40760, 40761, 40763, 40764, 40765, 40766);
  script_xref(name:"GLSA", value:"200801-18");

  script_name(english:"GLSA-200801-18 : Kazehakase: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200801-18
(Kazehakase: Multiple vulnerabilities)

    Kazehakase includes a copy of PCRE which is vulnerable to multiple
    buffer overflows and memory corruptions vulnerabilities (GLSA
    200711-30).
  
Impact :

    A remote attacker could entice a user to open specially crafted input
    (e.g bookmarks) with Kazehakase, which could possibly lead to the
    execution of arbitrary code, a Denial of Service or the disclosure of
    sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200801-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Kazehakase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/kazehakase-0.5.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kazehakase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/kazehakase", unaffected:make_list("ge 0.5.0"), vulnerable:make_list("lt 0.5.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Kazehakase");
}
