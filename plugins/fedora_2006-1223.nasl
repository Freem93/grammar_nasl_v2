#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1223.
#

include("compat.inc");

if (description)
{
  script_id(24054);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_xref(name:"FEDORA", value:"2006-1223");

  script_name(english:"Fedora Core 6 : kernel-2.6.18-1.2849.fc6 (2006-1223)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates to the latest upstream stable kernel (2.6.18.2), and also
fixes a number of security issues.

MOKB-05-11-2006: Linux 2.6.x ISO9660 __find_get_block_slow() denial of
service http://projects.info-pull.com/mokb/MOKB-05-11-2006.html
(CVE-2006-5757)

MOKB-07-11-2006: Linux 2.6.x zlib_inflate memory corruption
http://projects.info-pull.com/mokb/MOKB-07-11-2006.html

MOKB-09-11-2006: Linux 2.6.x ext3fs_dirhash denial of service
http://projects.info-pull.com/mokb/MOKB-10-11-2006.html

Herbert Xu found a security issue in the Xen hypervisor, which would
allow a malicious guest to access a freed grant table page after
freeing and possibly having it reallocated to another guest.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://projects.info-pull.com/mokb/MOKB-05-11-2006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://projects.info-pull.com/mokb/MOKB-07-11-2006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://projects.info-pull.com/mokb/MOKB-10-11-2006.html"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-November/000872.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f11a6c8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/12");
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
if (rpm_check(release:"FC6", reference:"kernel-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", cpu:"i386", reference:"kernel-PAE-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-debuginfo-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-debuginfo-common-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-devel-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-doc-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-headers-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-kdump-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-kdump-debuginfo-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-kdump-devel-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-xen-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-xen-debuginfo-2.6.18-1.2849.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"kernel-xen-devel-2.6.18-1.2849.fc6")) flag++;


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
