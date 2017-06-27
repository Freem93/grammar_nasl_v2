#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1203.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24049);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_xref(name:"FEDORA", value:"2006-1203");

  script_name(english:"Fedora Core 6 : texinfo-4.8-14.fc6 (2006-1203)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Sun Nov 5 2006 Miloslav Trmac <mitr at redhat.com> -
    4.8-14

    - Remove off-line sorting from texindex (fixes
      CVE-2006-4810)

    - Mon Oct 9 2006 Miloslav Trmac <mitr at redhat.com> -
      4.8-13

    - Don't use mode 0666 for the texindex temporary files

    - Mon Oct 9 2006 Miloslav Trmac <mitr at redhat.com> -
      4.8-12

    - Don't leave around temporary files used by texindex

    - Add missing error handling to
      texinfo-CVE-2005-3011.patch

    - Wed Jul 12 2006 Jesse Keating <jkeating at redhat.com>
      - 4.8-11.1

    - rebuild

    - Sat Mar 25 2006 Miloslav Trmac <mitr at redhat.com> -
      4.8-11

    - Split texinfo-tex from the texinfo package (#178406)

    - Ship COPYING, don't ship INSTALL

    - Sun Mar 19 2006 Miloslav Trmac <mitr at redhat.com> -
      4.8-10

    - Remove incorrect Prefix :

    - Drop info/README

    - Convert change log to UTF-8

    - Fri Feb 10 2006 Jesse Keating <jkeating at redhat.com>
      - 4.8-9.2

    - bump again for double-long bug on ppc(64)

    - Tue Feb 7 2006 Jesse Keating <jkeating at redhat.com>
      - 4.8-9.1

    - rebuilt for new gcc4.1 snapshot and glibc changes

    - Mon Jan 16 2006 Miloslav Trmac <mitr at redhat.com> -
      4.8-9

    - Fix handling of bzip2'ed files (#128637)

    - Mon Jan 16 2006 Miloslav Trmac <mitr at redhat.com> -
      4.8-8

    - Ignore scriptlet failures with --excludedocs (#166958)

    - Don't link texindex to zlib, don't pretend to link to
      zlib statically

    - Fri Dec 9 2005 Jesse Keating <jkeating at redhat.com>

    - rebuilt

    - Fri Oct 14 2005 Tim Waugh <twaugh at redhat.com> 4.8-7

    - Apply patch to fix CVE-2005-3011 (bug #169585).

    - Thu Jun 9 2005 Tim Waugh <twaugh at redhat.com> 4.8-6

    - Ship texi2pdf man page, taken from tetex-2.0.2 RPM.

    - Tue Jun 7 2005 Tim Waugh <twaugh at redhat.com> 4.8-5

    - Ship texi2pdf (bug #147271).

    - Mon Mar 14 2005 Tim Waugh <twaugh at redhat.com> 4.8-4

    - Requires tetex (bug #151075).

    - Wed Mar 2 2005 Tim Waugh <twaugh at redhat.com> 4.8-3

    - Rebuild for new GCC.

    - Mon Feb 7 2005 Tim Waugh <twaugh at redhat.com> 4.8-2

    - Don't ship texi2pdf (bug #147271).

    - Thu Feb 3 2005 Tim Waugh <twaugh at redhat.com> 4.8-1

    - 4.8.

    - Thu Dec 30 2004 Tim Waugh <twaugh at redhat.com> 4.7-6

    - Fixed URL (bug #143729).

    - Thu Aug 12 2004 Tim Waugh <twaugh at redhat.com> 4.7-5

    - Rebuilt.

    - Wed Jul 7 2004 Tim Waugh <twaugh at redhat.com> 4.7-4

    - Build for FC2.

    - Tue Jun 29 2004 Tim Waugh <twaugh at redhat.com> 4.7-3

    - Fix grouping in user-defined macros.

    - Mon Jun 28 2004 Tim Waugh <twaugh at redhat.com> 4.7-2

[plus 162 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-November/000852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb19d12c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:texinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:texinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:texinfo-tex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"info-4.8-14.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"texinfo-4.8-14.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"texinfo-debuginfo-4.8-14.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"texinfo-tex-4.8-14.fc6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "info / texinfo / texinfo-debuginfo / texinfo-tex");
}
