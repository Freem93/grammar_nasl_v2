#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2009.
#

include("compat.inc");

if (description)
{
  script_id(27743);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:54:54 $");

  script_cve_id("CVE-2007-2958");
  script_xref(name:"FEDORA", value:"2007-2009");

  script_name(english:"Fedora 7 : claws-mail-3.0.0-1.fc7 (2007-2009)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Sep 3 2007 Andreas Bierfert
    <andreas.bierfert[AT]lowlatency.de>

    - 3.0.0-1

    - version upgrade

    - new license tag (upstream switch to GPLv3+)

    - fix #254121 (CVE-2007-2958)

    - Wed Aug 22 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 2.10.0-4

    - new license tag

    - Wed Jul 18 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 2.10.0-3

    - build against libSM (#248675)

    - Mon Jul 16 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 2.10.0-2

    - add requires for bogofilter (#246125)

    - Tue Jul 3 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 2.10.0-1

    - version upgrade

    - fix #246230

    - Tue May 15 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de> 2.9.2-1

  - version upgrade

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-September/003596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af777da7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-plugins-bogofilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-plugins-clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-plugins-dillo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-plugins-pgp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:claws-mail-plugins-spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"claws-mail-3.0.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"claws-mail-debuginfo-3.0.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"claws-mail-devel-3.0.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"claws-mail-plugins-bogofilter-3.0.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"claws-mail-plugins-clamav-3.0.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"claws-mail-plugins-dillo-3.0.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"claws-mail-plugins-pgp-3.0.0-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"claws-mail-plugins-spamassassin-3.0.0-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "claws-mail / claws-mail-debuginfo / claws-mail-devel / etc");
}
