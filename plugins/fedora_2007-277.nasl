#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-277.
#

include("compat.inc");

if (description)
{
  script_id(24766);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:54:55 $");

  script_cve_id("CVE-2006-5753", "CVE-2007-0772");
  script_xref(name:"FEDORA", value:"2007-277");

  script_name(english:"Fedora Core 5 : kernel-2.6.19-1.2288.2.1.fc5 (2007-277)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated to kernel 2.6.19.5-rc1 plus additional fixes :

http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.19.4

2.6.19.5-rc1: 4 V4L fixes 3 usbaudio fixes 3 wireless driver fixes 2
IDE driver cable detection fixes NFS bugfix various other fixes

CVE-2007-0772: Summary: The Linux kernel before 2.6.20.1 allows remote
attackers to cause a denial of service (oops) via a crafted NFSACL 2
ACCESS request that triggers a free of an incorrect pointer.

CVE-2006-5753: Summary: Unspecified vulnerability in the listxattr
system call in Linux kernel, when a 'bad inode' is present, allows
local users to cause a denial of service (data corruption) and
possibly gain privileges via unknown vectors.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.19.4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-March/001524.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?491f7f5c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/06");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"kernel-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debug-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debug-devel-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debuginfo-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-devel-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-doc-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-kdump-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-kdump-devel-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-debug-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-debug-devel-2.6.19-1.2288.2.1.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-devel-2.6.19-1.2288.2.1.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-devel / kernel-debuginfo / etc");
}
