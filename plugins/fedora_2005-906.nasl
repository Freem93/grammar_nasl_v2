#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-906.
#

include("compat.inc");

if (description)
{
  script_id(19869);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:38:06 $");

  script_xref(name:"FEDORA", value:"2005-906");

  script_name(english:"Fedora Core 4 : kernel-2.6.12-1.1456_FC4 (2005-906)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Sep 22 2005 Dave Jones <davej at redhat.com>
    [2.6.12-1.1456_FC4]

    - Disable crash driver on Xen kernels.

  - Wed Sep 14 2005 Dave Jones <davej at redhat.com>
    [2.6.12-1.1455_FC4]

    - Fixes for CVE-2005-2490 and CVE-2005-2492

  - Thu Sep 8 2005 Rik van Riel <riel at redhat.com>

    - upgrade to a newer Xen snapshot

    - exclude Xen TPM bits, since those conflict with
      2.6.12.5

    - enable highmem for Xen kernels (#162226)

    - add workaround for glibc bug on VDSO note parsing
      (Roland) (#166984)

  - Mon Sep 5 2005 Dave Jones <davej at redhat.com>

    - Fix aic7xxx issue with >4GB. (#167049)

  - Fri Sep 2 2005 Dave Jones <davej at redhat.com>

    - Various post 2.6.13 ACPI updates. (20050902)

  - Mon Aug 29 2005 Dave Jones <davej at redhat.com>

    - Fix local builds when '-' is in the hostname.

    - Update ALPS driver to 2.6.13 level.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-September/001397.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b44697c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"kernel-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-debuginfo-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-devel-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-doc-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-smp-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-smp-devel-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xen0-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xen0-devel-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xenU-2.6.12-1.1456_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xenU-devel-2.6.12-1.1456_FC4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-devel / kernel-doc / kernel-smp / etc");
}
