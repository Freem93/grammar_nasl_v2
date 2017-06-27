#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-1013.
#

include("compat.inc");

if (description)
{
  script_id(20078);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_cve_id("CVE-2005-2973");
  script_xref(name:"FEDORA", value:"2005-1013");

  script_name(english:"Fedora Core 4 : kernel-2.6.13-1.1532_FC4 (2005-1013)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Oct 19 2005 Dave Jones <davej at redhat.com>
    [2.6.13-1.1532_FC4]

    - Fix CVE-2005-2973 (ipv6 infinite loop)

    - Disable ACPI burst again, it's still problematic.

    - Update to the final upstream variant of the IDE/SATA
      fix.

  - Sun Oct 16 2005 Dave Jones <davej at redhat.com>
    [2.6.13-1.1531_FC4]

    - Stop IDE claiming legacy ports before libata in
      combined mode.

  - Sun Oct 16 2005 Dave Jones <davej at redhat.com>
    [2.6.13-1.1530_FC4]

    - Enable ACPI EC burst.

    - Reenable change of timesource default.

  - Tue Oct 11 2005 Dave Jones <davej at redhat.com>
    [2.6.13-1.1529_FC4]

    - 2.6.13.4

  - Thu Oct 6 2005 Dave Jones <davej at redhat.com>

    - Fix information leak in orinoco driver.

  - Wed Oct 5 2005 Dave Jones <davej at redhat.com>

    - Further fixing to the 8139too suspend/resume problem.

  - Mon Oct 3 2005 Dave Jones <davej at redhat.com>
    [2.6.13-1.1528_FC4]

    - 2.6.13.3

  - Sun Oct 2 2005 Dave Jones <davej at redhat.com>
    [2.6.13-1.1527_FC4]

    - Disable debug messages in w83781d sensor driver.
      (#169695)

    - Re-add a bunch of patches that got accidentally
      dropped in last update.

    - Fix suspend/resume with 8139too

    - Fix usbhid/wireless security lock clash (#147479)

    - Missing check condition in ide scsi (#160868)

    - Fix nosense error with transcend usb keys (#162559)

    - Fix sk98lin vpd problem. (#136158)

    - Fix IDE floppy eject. (#158548)

  - Fri Sep 30 2005 Dave Jones <davej at redhat.com>

    - irda-driver smsc-ircc2 needs pnp-functionality.
      (#153970)

    - Reenable /proc/acpi/sleep (#169650)

    - Silence some selinux messages. (#167852)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-October/001507.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d6026a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/24");
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
if (rpm_check(release:"FC4", reference:"kernel-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-debuginfo-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-devel-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-doc-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-smp-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", reference:"kernel-smp-devel-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xen0-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xen0-devel-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xenU-2.6.13-1.1532_FC4")) flag++;
if (rpm_check(release:"FC4", cpu:"i386", reference:"kernel-xenU-devel-2.6.13-1.1532_FC4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-devel / kernel-doc / kernel-smp / etc");
}
