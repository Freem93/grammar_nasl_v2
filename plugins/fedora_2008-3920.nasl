#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3920.
#

include("compat.inc");

if (description)
{
  script_id(32344);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:23:15 $");

  script_cve_id("CVE-2008-1928");
  script_xref(name:"FEDORA", value:"2008-3920");

  script_name(english:"Fedora 7 : perl-Imager-0.64-2.fc7 (2008-3920)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Apr 24 2008 Steven Pritchard <steve at kspei.com>
    0.64-2

    - Rebuild.

    - Thu Apr 24 2008 Steven Pritchard <steve at kspei.com>
      0.64-1

    - Update to 0.64 (CVE-2008-1928).

    - Add versioned Test::More BR.

    - Thu Mar 6 2008 Tom 'spot' Callaway <tcallawa at
      redhat.com> - 0.62-3

    - rebuild for new perl

    - Tue Feb 19 2008 Fedora Release Engineering <rel-eng at
      fedoraproject.org> - 0.62-2

    - Autorebuild for GCC 4.3

    - Tue Dec 11 2007 Steven Pritchard <steve at kspei.com>
      0.62-1

    - Update to 0.62.

    - Update License tag.

    - Mon Sep 17 2007 Steven Pritchard <steve at kspei.com>
      0.60-1

    - Update to 0.60.

    - Wed Aug 29 2007 Fedora Release Engineering <rel-eng at
      fedoraproject dot org> - 0.59-2

    - Rebuild for selinux ppc32 issue.

    - Tue Jun 26 2007 Steven Pritchard <steve at kspei.com>
      0.59-1

    - Update to 0.59.

    - Fri May 18 2007 Steven Pritchard <steve at kspei.com>
      0.58-1

    - Update to 0.58.

    - Drop hack to change location of rgb.txt (fixed
      upstream).

    - BR Image::Math::Constrain and Affix::Infix2Postfix for
      better test coverage.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=443938"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-May/009926.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0b4cc42"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-Imager package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Imager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"perl-Imager-0.64-2.fc7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Imager");
}
