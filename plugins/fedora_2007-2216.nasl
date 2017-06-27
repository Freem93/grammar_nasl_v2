#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2216.
#

include("compat.inc");

if (description)
{
  script_id(27760);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/05 16:01:14 $");

  script_cve_id("CVE-2007-3388", "CVE-2007-4137");
  script_bugtraq_id(23269, 25154);
  script_xref(name:"FEDORA", value:"2007-2216");

  script_name(english:"Fedora 7 : qt-3.3.8-7.fc7 (2007-2216)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Sep 17 2007 Than Ngo <than at redhat.com> -
    1:3.3.8-7

    - bz292941, CVE-2007-4137

    - Wed Aug 29 2007 Than Ngo <than at redhat.com> -
      1:3.3.8-6.fc7.1

    - cleanup security patch

    - Tue Aug 28 2007 Than Ngo <than at redhat.com> -
      1:3.3.8-6.fc7

    - CVE-2007-3388 qt3 format string flaw

    - Thu Jun 14 2007 Than Ngo <than at redhat.com> -
      1:3.3.8-5.fc7.1

    - backport to fix #bz243722, bz#244148, Applications
      using qt-mysql crash if database is removed before
      QApplication is destroyed

  - Mon Apr 23 2007 Than Ngo <than at redhat.com> -
    1:3.3.8-5.fc7

    - apply patch to fix fontrendering problem in gu_IN
      #228451,#228452

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=292941"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-September/003847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9553a56"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-ODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-PostgreSQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/18");
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
if (rpm_check(release:"FC7", reference:"qt-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-MySQL-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-ODBC-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-PostgreSQL-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-config-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-debuginfo-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-designer-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-devel-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-devel-docs-3.3.8-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt-sqlite-3.3.8-7.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt / qt-MySQL / qt-ODBC / qt-PostgreSQL / qt-config / qt-debuginfo / etc");
}
