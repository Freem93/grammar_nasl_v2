#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2361.
#

include("compat.inc");

if (description)
{
  script_id(27769);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2007-3820", "CVE-2007-4224", "CVE-2007-4225", "CVE-2007-4569");
  script_xref(name:"FEDORA", value:"2007-2361");

  script_name(english:"Fedora 7 : kdebase-3.5.7-13.1.fc7 (2007-2361)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Oct 2 2007 Than Ngo <than at redhat.com> -
    6:3.5.7-13.1

    - rh#299731, CVE-2007-4569

    - Wed Aug 15 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> 6:3.5.7-13

    - CVE-2007-3820, CVE-2007-4224, CVE-2007-4225

    - License: GPLv2

    - Requires: kdelibs3(-devel)

    - Fri Jul 20 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> - 6:3.5.7-12

    - fix unpackaged files

    - Fri Jul 20 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> - 6:3.5.7-9

    - %ifnarch s390 s390x: BR: lm_sensors

    - Thu Jul 19 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> - 6:3.5.7-7

    - omit dirs owned by kde-filesystem

    - Mon Jul 2 2007 Than Ngo <than at redhat.com> -
      6:3.5.7-6

    - fix bz#244906

    - Wed Jun 20 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> - 6:3.5.7-5

    - Provides: kdebase3(-devel)

    - Wed Jun 20 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> - 6:3.5.7-4

    - -devel: Requires: %name...

    - portability++

    - Fri Jun 15 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> - 6:3.5.7-3

    - specfile portability

    - Mon Jun 11 2007 Rex Dieter
      <rdieter[AT]fedoraproject.org> - 6:3.5.7-2

    - fix BR: kdelibs-devel

    - cleanup Req's wrt kde-settings

    - Mon Jun 11 2007 Than Ngo <than at redhat.com> -
      6:3.5.7-1.fc7.1

    - remove kdebase-3.4.2-npapi-64bit-fixes.patch, it's
      included in new upstream

  - Wed Jun 6 2007 Than Ngo <than at redhat.com> -
    6:3.5.7-0.1

    - 3.5.7

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=299731"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-October/003992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cca76192"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-extras");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC7", reference:"kdebase-3.5.7-13.1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase-debuginfo-3.5.7-13.1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase-devel-3.5.7-13.1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase-extras-3.5.7-13.1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase / kdebase-debuginfo / kdebase-devel / kdebase-extras");
}
