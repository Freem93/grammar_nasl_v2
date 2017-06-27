#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-510.
#

include("compat.inc");

if (description)
{
  script_id(18604);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:38:05 $");

  script_xref(name:"FEDORA", value:"2005-510");

  script_name(english:"Fedora Core 4 : kernel-2.6.12-1.1387_FC4 (2005-510)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jun 29 2005 Dave Jones <davej at redhat.com>

    - 2.6.12.2

  - Mon Jun 27 2005 Dave Jones <davej at redhat.com>

    - Disable multipath caches. (#161168)

    - Reenable AMD756 I2C driver for x86-64. (#159609)

    - Add more IBM r40e BIOS's to the C2/C3 blacklist.

  - Thu Jun 23 2005 Dave Jones <davej at redhat.com>

    - Make orinoco driver suck less.
      (Scanning/roaming/ethtool support).

  - Exec-shield randomisation fix.

    - pwc driver warning fix.

    - Prevent potential oops in tux with symlinks. (#160219)

  - Wed Jun 22 2005 Dave Jones <davej at redhat.com>

    - 2.6.12.1

    - Clean up subthread exec (CVE-2005-1913)

    - ia64 ptrace + sigrestore_context (CVE-2005-1761)

  - Wed Jun 22 2005 David Woodhouse <dwmw2 at redhat.com>

    - Update audit support

  - Mon Jun 20 2005 Dave Jones <davej at redhat.com>

    - Rebase to 2.6.12

    - Temporarily drop Alans IDE fixes whilst they get
      redone.

    - Enable userspace queueing of ipv6 packets.

  - Tue Jun 7 2005 Dave Jones <davej at redhat.com>

    - Drop recent b44 changes which broke some setups.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-July/001023.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39665b64"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/05");
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
if (rpm_check(release:"FC4", reference:"kernel-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-debuginfo-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-devel-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-doc-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-smp-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-smp-devel-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xen0-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xen0-devel-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xenU-2.6.12-1.1387_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xenU-devel-2.6.12-1.1387_FC4")) flag++;


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
