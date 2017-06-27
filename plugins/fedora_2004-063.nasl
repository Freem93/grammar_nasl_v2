#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-063.
#

include("compat.inc");

if (description)
{
  script_id(13675);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 21:09:30 $");

  script_xref(name:"FEDORA", value:"2004-063");

  script_name(english:"Fedora Core 1 : kernel-2.4.22-1.2166.nptl (2004-063)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Jan 26 2004 Dave Jones <davej at redhat.com>

    - Fix error in wan config files that broke some
      configurators.

    - Reenable VIA DRI.

  - Fri Jan 16 2004 Dave Jones <davej at redhat.com>

    - Merge VM updates from post 2.4.22

    - Fix AMD64 ptrace security hole. (CVE-2004-0001)

    - Fix NPTL SMP hang.

    - Merge bits from 2.4.25pre

    - R128 DRI limits checking. (CVE-2004-0003)

    - Various ymfpci fixes.

    - tmpfs readdir does not update dir atime

    - Minor IPV4/Netfilter changes.

    - Fix userspace dereferencing bug in USB Vicam driver.

    - Merge a few more bits from 2.4.23pre

    - Numerous tmpfs fixes.

    - Use list_add_tail in buffer_insert_list

    - Correctly dequeue SIGSTOP signals in kupdated

    - Update laptop-mode patch to match mainline.

  - Wed Jan 14 2004 Dave Jones <davej at redhat.com>

    - Merge a few more missing netfilter fixes from
      upstream.

  - Tue Jan 13 2004 Dave Jones <davej at redhat.com>

    - Reenable Tux.

    - Lots of updates from the 2.4.23 era.

  - Mon Jan 12 2004 Dave Jones <davej at redhat.com>

    - Avoid deadlocks in USB storage.

  - Fri Jan 09 2004 Dave Jones <davej at redhat.com>

    - Fix thread creation race.

  - Thu Jan 08 2004 Dave Jones <davej at redhat.com>

    - USB storage: Make Pentax Optio S4 work

    - Config file tweaking. Only enable CONFIG_SIBLINGS_2 on
      the kernels that need it.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-February/000055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27d8f9ee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-2.4.22-1.2166.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-BOOT-2.4.22-1.2166.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-debuginfo-2.4.22-1.2166.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-doc-2.4.22-1.2166.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-smp-2.4.22-1.2166.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-source-2.4.22-1.2166.nptl")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-debuginfo / kernel-doc / kernel-smp / etc");
}
