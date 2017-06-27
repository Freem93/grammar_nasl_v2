#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-0096.
#

include("compat.inc");

if (description)
{
  script_id(51512);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2010-4534", "CVE-2010-4535");
  script_osvdb_id(70159, 70160);
  script_xref(name:"FEDORA", value:"2011-0096");

  script_name(english:"Fedora 13 : Django-1.2.4-1.fc13 (2011-0096)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Jan 3 2011 Steve 'Ashcrow' Milner <me at
    stevemilner.org> - 1.2.4-1

    - Update for multiple security issues (see
      http://www.djangoproject.com/weblog/2010/dec/22/securi
      ty/)

    - Sat Oct 9 2010 Steve 'Ashcrow' Milner <me at
      stevemilner.org> - 1.2.3-3

    - Now build docs for F12+

    - Added Django-remove-djangodocs-ext.patch

    - Sat Oct 9 2010 Steve 'Ashcrow' Milner <me at
      stevemilner.org> - 1.2.3-2

    - Moved to dirhtml for documentation generation

    - Mon Sep 13 2010 Steve 'Ashcrow' Milner <me at
      stevemilner.org> - 1.2.3-1

    - Update for
      http://www.djangoproject.com/weblog/2010/sep/10/123/

    - Thu Sep 9 2010 Steve 'Ashcrow' Milner <me at
      stevemilner.org> - 1.2.2-1

    - Update for CVE-2010-3082 (see
      http://www.djangoproject.com/weblog/2010/sep/08/securi
      ty-release/)

    - Removed Django-hash-compat-13310.patch as it is
      already included in this release

    - Wed Jul 21 2010 David Malcolm <dmalcolm at redhat.com>
      - 1.2.1-6

    - Rebuilt for
      https://fedoraproject.org/wiki/Features/Python_2.7/Mas
      sRebuild

    - Tue Jun 8 2010 Steve 'Ashcrow' Milner <stevem at
      gnulinux.net> - 1.2.1-5

    - Added
      http://code.djangoproject.com/changeset/13310?format=d
      iff&new=13310 per BZ#601212

    - Thu Jun 3 2010 Steve 'Ashcrow' Milner <stevem at
      gnulinux.net> - 1.2.1-4

    - Include egg in >= rhel6

    - Thu Jun 3 2010 Michel Salim <salimma at
      fedoraproject.org> - 1.2.1-3

    - Use generated %{name}.lang instead of including each
      locale file by hand

    - Temporarily make main package provide -doc on Rawhide,
      to fix upgrade path until upstream documentation
      builds with Sphinx 1.0

  - Thu May 27 2010 Steve 'Ashcrow' Milner <stevem at
    gnulinux.net> - 1.2.1-2

    - Allow for building docs in F13 as it's only F14
      freaking out

    - Tue May 25 2010 Steve 'Ashcrow' Milner <stevem at
      gnulinux.net> - 1.2.1-1

    - Update for new release.

    - Added lang files per BZ#584866.

    - Changed perms on
      %{python_sitelib}/django/contrib/admin/media/js/compre
      ss.py

    - Lots of explicit files listed in %files in order to
      reduce duplicate file listings

    - Docs are not built on F-13 for now

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://code.djangoproject.com/changeset/13310?format=diff&new=13310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.djangoproject.com/weblog/2010/dec/22/security/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.djangoproject.com/weblog/2010/sep/08/security-release/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.djangoproject.com/weblog/2010/sep/10/123/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=665373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Features/Python_2.7/MassRebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/053041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f21a156f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"Django-1.2.4-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Django");
}
