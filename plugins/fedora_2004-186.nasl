#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-186.
#

include("compat.inc");

if (description)
{
  script_id(13731);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/21 21:09:31 $");

  script_cve_id("CVE-2004-0495", "CVE-2004-0535", "CVE-2004-0554", "CVE-2004-0587");
  script_xref(name:"FEDORA", value:"2004-186");

  script_name(english:"Fedora Core 1 : kernel-2.4.22-1.2194.nptl (2004-186)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Numerous problems referencing userspace memory were identified in
several device drivers by Al Viro using the sparse tool. The Common
Vulnerabilities and Exposures project (cve.mitre.org) assigned the
name CVE-2004-0495 to this issue.

A problem was found where userspace code could execute certain
floating point instructions from signal handlers which would cause the
kernel to lock up. The Common Vulnerabilities and Exposures project
(cve.mitre.org) assigned the name CVE-2004-0554 to this issue.

Previous kernels contained a patch against the framebuffer ioctl code
which turned out to be unnecessary. This has been dropped in this
update.

A memory leak in the E1000 network card driver has been fixed. The
Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
the name CVE-2004-0535 to this issue.

Previously, inappropriate permissions were set on
/proc/scsi/qla2300/HbaApiNode The Common Vulnerabilities and Exposures
project (cve.mitre.org) assigned the name CVE-2004-0587 to this issue.

Support for systems with more than 4GB of memory was previously
unavailable. The 686 SMP kernel now supports this configuration.
(Bugzilla #122960) Support for SMP on 586's was also previously not
included. This has also been rectified. (Bugzilla #111871)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-June/000183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8629097"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/23");
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
if (rpm_check(release:"FC1", reference:"kernel-2.4.22-1.2194.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-BOOT-2.4.22-1.2194.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-debuginfo-2.4.22-1.2194.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-doc-2.4.22-1.2194.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-smp-2.4.22-1.2194.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-source-2.4.22-1.2194.nptl")) flag++;


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
