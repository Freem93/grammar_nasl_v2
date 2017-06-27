#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201001-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(44893);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/13 14:12:00 $");

  script_cve_id("CVE-2009-3692", "CVE-2009-3940");
  script_osvdb_id(58652, 60098);
  script_xref(name:"GLSA", value:"201001-04");

  script_name(english:"GLSA-201001-04 : VirtualBox: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201001-04
(VirtualBox: Multiple vulnerabilities)

    Thomas Biege of SUSE discovered multiple vulnerabilities:
    A shell metacharacter injection in popen() (CVE-2009-3692) and
    a possible buffer overflow in strncpy() in the VBoxNetAdpCtl
    configuration tool.
    An unspecified vulnerability in VirtualBox
    Guest Additions (CVE-2009-3940).
  
Impact :

    A local, unprivileged attacker with the permission to run VirtualBox
    could gain root privileges. A guest OS local user could cause a Denial
    of Service (memory consumption) on the guest OS via unknown vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201001-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users of the binary version of VirtualBox should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-bin-3.0.12'
    All users of the Open Source version of VirtualBox should upgrade to
    the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-ose-3.0.12'
    All users of the binary VirtualBox Guest Additions should upgrade to
    the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-guest-additions-3.0.12'
    All users of the Open Source VirtualBox Guest Additions should upgrade
    to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-emulation/virtualbox-ose-additions-3.0.12'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-guest-additions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-ose-additions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-emulation/virtualbox-guest-additions", unaffected:make_list("ge 3.0.12"), vulnerable:make_list("lt 3.0.12"))) flag++;
if (qpkg_check(package:"app-emulation/virtualbox-ose-additions", unaffected:make_list("ge 3.0.12"), vulnerable:make_list("lt 3.0.12"))) flag++;
if (qpkg_check(package:"app-emulation/virtualbox-bin", unaffected:make_list("ge 3.0.12"), vulnerable:make_list("lt 3.0.12"))) flag++;
if (qpkg_check(package:"app-emulation/virtualbox-ose", unaffected:make_list("ge 3.0.12"), vulnerable:make_list("lt 3.0.12"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VirtualBox");
}
