#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14538);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0419");
  script_osvdb_id(6502);
  script_xref(name:"GLSA", value:"200407-05");

  script_name(english:"GLSA-200407-05 : XFree86, X.org: XDM ignores requestPort setting");
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
"The remote host is affected by the vulnerability described in GLSA-200407-05
(XFree86, X.org: XDM ignores requestPort setting)

    XDM will open TCP sockets for its chooser, even if the
    DisplayManager.requestPort setting is set to 0. Remote clients can use this
    port to connect to XDM and request a login window, thus allowing access to
    the system.
  
Impact :

    Authorized users may be able to login remotely to a machine running XDM,
    even if this option is disabled in XDM's configuration. Please note that an
    attacker must have a preexisting account on the machine in order to exploit
    this vulnerability.
  
Workaround :

    There is no known workaround at this time. All users should upgrade to the
    latest available version of X."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.xfree86.org/show_bug.cgi?id=1376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"If you are using XFree86, you should run the following:
    # emerge sync
    # emerge -pv '>=x11-base/xfree-4.3.0-r6'
    # emerge '>=x11-base/xfree-4.3.0-r6'
    If you are using X.org's X11 server, you should run the following:
    # emerge sync
    # emerge -pv '>=x11-base/xorg-x11-6.7.0-r1'
    # emerge '>=x11-base/xorg-x11-6.7.0-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xfree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/30");
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

if (qpkg_check(package:"x11-base/xfree", unaffected:make_list("ge 4.3.0-r6"), vulnerable:make_list("le 4.3.0-r5"))) flag++;
if (qpkg_check(package:"x11-base/xorg-x11", unaffected:make_list("ge 6.7.0-r1"), vulnerable:make_list("le 6.7.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "XFree86 / X.org");
}
