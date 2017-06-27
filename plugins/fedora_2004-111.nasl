#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-111.
#

include("compat.inc");

if (description)
{
  script_id(13692);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/10/21 21:09:31 $");

  script_cve_id("CVE-2004-0133", "CVE-2004-0178", "CVE-2004-0181", "CVE-2004-0228", "CVE-2004-0394", "CVE-2004-0427");
  script_xref(name:"FEDORA", value:"2004-111");

  script_name(english:"Fedora Core 1 : kernel-2.4.22-1.2188.nptl (2004-111)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A memory leak was fixed in an error path in the do_fork() routine.
This was unlikely to have caused problems in real world situations.

The information leak fixed in the previous errata was also found to
affect XFS and JFS. The Common Vulnerabilities and Exposures project
(cve.mitre.org) assigned the names CVE-2004-0133 and CVE-2004-0181
respectively.

A vulnerability in the OSS code for SoundBlaster 16 devices was
discovered by Andreas Kies. It is possible for local users with access
to the sound system to crash the machine (CVE-2004-0178).

An automated checked from http://www.coverity.com highlighted a range
checking bug in the i810 DRM driver. This was fixed by Andrea
Arcangeli and Chris Wright.

Arjan van de Ven discovered the framebuffer code was doing direct
userspace accesses instead of using correct interfaces to write to
userspace.

Brad Spengler found a signedness issue in the cpufreq proc handler
which could lead to users being able to read arbitary regions of
kernel memory. This was fixed by Dominik Brodowski.

Shaun Colley found a potential buffer overrun in the panic() function.
As this function does not ever return, it is unlikely that this is
exploitable, but has been fixed nonetheless. The Common
Vulnerabilities and Exposures project (cve.mitre.org) assigned the
name CVE-2004-0394 to this issue.

Paul Starzetz and Wojciech Purczynski found a lack of bounds checking
in the MCAST_MSFILTER socket option which allows user code to write
into kernel space, potentially giving the attacker full root
priveledges. There has already been proof of concept code published
exploiting this hole in a local denial-of-service manner.
http://www.isec.pl/vulnerabilities/isec-0015-msfilter.txt has more
information. The Common Vulnerabilities and Exposures project
(cve.mitre.org) assigned the name CVE-2004-0424 to this issue.

The previous security errata actually missed fixes for several
important problems. This has been corrected in this update.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.coverity.com"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isec.pl/vulnerabilities/isec-0015-msfilter.txt"
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-April/000109.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e64ee995"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/22");
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
if (rpm_check(release:"FC1", reference:"kernel-2.4.22-1.2188.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-BOOT-2.4.22-1.2188.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-debuginfo-2.4.22-1.2188.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-doc-2.4.22-1.2188.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-smp-2.4.22-1.2188.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-source-2.4.22-1.2188.nptl")) flag++;


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
