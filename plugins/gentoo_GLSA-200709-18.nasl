#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200709-18.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(26216);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-4538", "CVE-2007-4539", "CVE-2007-4543");
  script_osvdb_id(37201, 37202, 37203);
  script_xref(name:"GLSA", value:"200709-18");

  script_name(english:"GLSA-200709-18 : Bugzilla: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200709-18
(Bugzilla: Multiple vulnerabilities)

    Masahiro Yamada found that from the 2.17.1 version, Bugzilla does not
    properly sanitize the content of the 'buildid' parameter when filing
    bugs (CVE-2007-4543). The next two vulnerabilities only affect Bugzilla
    2.23.3 or later, hence the stable Gentoo Portage tree does not contain
    these two vulnerabilities: Loic Minier reported that the
    'Email::Send::Sendmail()' function does not properly sanitise 'from'
    email information before sending it to the '-f' parameter of
    /usr/sbin/sendmail (CVE-2007-4538), and Frederic Buclin discovered that
    the XML-RPC interface does not correctly check permissions in the
    time-tracking fields (CVE-2007-4539).
  
Impact :

    A remote attacker could trigger the 'buildid' vulnerability by sending
    a specially crafted form to Bugzilla, leading to a persistent XSS, thus
    allowing for theft of credentials. With Bugzilla 2.23.3 or later, an
    attacker could also execute arbitrary code with the permissions of the
    web server by injecting a specially crafted 'from' email address and
    gain access to normally restricted time-tracking information through
    the XML-RPC service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200709-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Bugzilla users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose www-apps/bugzilla"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(79, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/bugzilla", unaffected:make_list("rge 2.20.5", "rge 2.22.3", "ge 3.0.1", "rge 2.22.5", "rge 2.20.6"), vulnerable:make_list("lt 3.0.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Bugzilla");
}
