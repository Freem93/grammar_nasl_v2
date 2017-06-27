#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-421.
#

include("compat.inc");

if (description)
{
  script_id(21252);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_xref(name:"FEDORA", value:"2006-421");

  script_name(english:"Fedora Core 5 : kernel-2.6.16-1.2096_FC5 (2006-421)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes a number of security issues that have been fixed
upstream over the last week or so.

i386/x86-64: Fix x87 information leak between processes
(CVE-2006-1056) ip_route_input panic fix (CVE-2006-1525) fix
MADV_REMOVE vulnerability (CVE-2006-1524) shmat: stop mprotect from
giving write permission to a readonly attachment (CVE-2006-1524) Fix
MPBL0010 driver insecure sysfs permissions x86_64: When user could
have changed RIP always force IRET (CVE-2006-0744) Fix RCU signal
handling Keys: Fix oops when adding key to non-keyring (CVE-2006-1522)
sysfs: zero terminate sysfs write buffers (CVE-2006-1055)

It also includes various other fixes from the -stable tree. Full
changelogs are available from :

http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.9
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.8
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.7
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.6
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.5
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.4
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.3
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.2

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.9"
  );
  # https://lists.fedoraproject.org/pipermail/announce/2006-April/002127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e8daedf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"kernel-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debuginfo-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-devel-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-doc-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-kdump-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-kdump-devel-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-devel-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen0-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen0-devel-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xenU-2.6.16-1.2096_FC5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xenU-devel-2.6.16-1.2096_FC5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-devel / kernel-doc / etc");
}
