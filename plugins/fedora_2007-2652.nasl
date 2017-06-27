#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2652.
#

include("compat.inc");

if (description)
{
  script_id(27784);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:54:55 $");

  script_cve_id("CVE-2007-5585");
  script_xref(name:"FEDORA", value:"2007-2652");

  script_name(english:"Fedora 7 : rss-glx-0.8.1.p-15.fc7 / tempest-0-0.4.20070929.fc7 / xscreensaver-5.03-12.fc7 (2007-2652)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A bug was reported that xscreensaver unlocking password dialog crashes
randomly. It is found this problem occurs when GL hack is launched
without gl helper binary installed. The new three packages fixes this
issue. Now packages which contain GL xscreensaver hacks also install
gl helper binary correctly.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=336331"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-October/004304.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a7d9bac"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-October/004305.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54277f20"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-October/004306.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90f5050a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rss-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rss-glx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rss-glx-gnome-screensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rss-glx-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rss-glx-xscreensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tempest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tempest-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tempest-gnome-screensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tempest-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tempest-xscreensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xscreensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xscreensaver-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xscreensaver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xscreensaver-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xscreensaver-extras-gss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xscreensaver-gl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xscreensaver-gl-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xscreensaver-gl-extras-gss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/24");
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
if (rpm_check(release:"FC7", reference:"rss-glx-0.8.1.p-15.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"rss-glx-debuginfo-0.8.1.p-15.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"rss-glx-gnome-screensaver-0.8.1.p-15.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"rss-glx-kde-0.8.1.p-15.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"rss-glx-xscreensaver-0.8.1.p-15.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"tempest-0-0.4.20070929.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"tempest-debuginfo-0-0.4.20070929.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"tempest-gnome-screensaver-0-0.4.20070929.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"tempest-kde-0-0.4.20070929.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"tempest-xscreensaver-0-0.4.20070929.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xscreensaver-5.03-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xscreensaver-base-5.03-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xscreensaver-debuginfo-5.03-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xscreensaver-extras-5.03-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xscreensaver-extras-gss-5.03-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xscreensaver-gl-base-5.03-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xscreensaver-gl-extras-5.03-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xscreensaver-gl-extras-gss-5.03-12.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rss-glx / rss-glx-debuginfo / rss-glx-gnome-screensaver / etc");
}
