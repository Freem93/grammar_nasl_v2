#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200810-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(34383);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:11:58 $");

  script_cve_id("CVE-2008-4394");
  script_osvdb_id(50059);
  script_xref(name:"GLSA", value:"200810-02");

  script_name(english:"GLSA-200810-02 : Portage: Untrusted search path local root vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200810-02
(Portage: Untrusted search path local root vulnerability)

    The Gentoo Security Team discovered that several ebuilds, such as
    sys-apps/portage, net-mail/fetchmail or app-editors/leo execute Python
    code using 'python -c', which includes the current working directory in
    Python's module search path. For several ebuild functions, Portage did
    not change the working directory from emerge's working directory.
  
Impact :

    A local attacker could place a specially crafted Python module in a
    directory (such as /tmp) and entice the root user to run commands such
    as 'emerge sys-apps/portage' from that directory, resulting in the
    execution of arbitrary Python code with root privileges.
  
Workaround :

    Do not run 'emerge' from untrusted working directories."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200810-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Portage users should upgrade to the latest version:
    # cd /root
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-apps/portage-2.1.4.5'
    NOTE: To upgrade to Portage 2.1.4.5 using 2.1.4.4 or prior, you must
    run emerge from a trusted working directory, such as '/root'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:portage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/10");
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

if (qpkg_check(package:"sys-apps/portage", unaffected:make_list("ge 2.1.4.5"), vulnerable:make_list("lt 2.1.4.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Portage");
}
