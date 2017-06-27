#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200510-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19849);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-3149");
  script_osvdb_id(19741);
  script_xref(name:"GLSA", value:"200510-03");

  script_name(english:"GLSA-200510-03 : Uim: Privilege escalation vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200510-03
(Uim: Privilege escalation vulnerability)

    Masanari Yamamoto discovered that Uim uses environment variables
    incorrectly. This bug causes a privilege escalation if setuid/setgid
    applications are linked to libuim. This bug only affects
    immodule-enabled Qt (if you build Qt 3.3.2 or later versions with
    USE='immqt' or USE='immqt-bc').
  
Impact :

    A malicious local user could exploit this vulnerability to execute
    arbitrary code with escalated privileges.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.freedesktop.org/pipermail/uim/2005-September/001346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200510-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Uim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-i18n/uim-0.4.9.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:uim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/01");
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

if (qpkg_check(package:"app-i18n/uim", unaffected:make_list("ge 0.4.9.1"), vulnerable:make_list("lt 0.4.9.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Uim");
}
