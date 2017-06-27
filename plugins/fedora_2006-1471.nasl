#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1471.
#

include("compat.inc");

if (description)
{
  script_id(24077);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_bugtraq_id(21353, 21604);
  script_xref(name:"FEDORA", value:"2006-1471");

  script_name(english:"Fedora Core 6 : kernel-2.6.18-1.2868.fc6 (2006-1471)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update rebases to 2.6.18.6rc2, which fixes the following security
bugs :

bridge: fix possible overflow in get_fdb_entries (CVE-2006-5751)

Bluetooth: Add packet size checks for CAPI messages (CVE-2006-6106)

In addition, a number of non-security related bugs have been fixed.
Complete changelogs are available at

http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.18.4
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.18.5
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.18.6

Additional Fedora specific changes detailed below.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.18.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.18.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.18.6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-December/001138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ad7116d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"kernel-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", cpu:"i386", reference:"kernel-PAE-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-debuginfo-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-debuginfo-common-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-devel-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-doc-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-headers-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-kdump-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-kdump-debuginfo-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-kdump-devel-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-xen-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-xen-debuginfo-2.6.18-1.2868.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-xen-devel-2.6.18-1.2868.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
}
