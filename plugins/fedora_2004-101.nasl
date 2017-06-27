#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-101.
#

include("compat.inc");

if (description)
{
  script_id(13685);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/10/21 21:09:30 $");

  script_cve_id("CVE-2004-0109");
  script_xref(name:"FEDORA", value:"2004-101");

  script_name(english:"Fedora Core 1 : kernel-2.4.22-1.2179.nptl (2004-101)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"iDefense reported a buffer overflow flaw in the ISO9660 filesystem
code. An attacker could create a malicious filesystem in such a way
that they could gain root privileges if that filesystem is mounted.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0109 to this issue.

Solar Designer from OpenWall discovered a minor information leak in
the ext3 filesystem code due to the lack of initialization of journal
descriptor blocks. This flaw has only minor security implications and
exploitation requires privileged access to the raw device. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0133 to this issue.

These packages also contain an updated fix with additional checks for
issues in the R128 Direct Render Infrastructure. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0003 to this issue.

Additionally, additional hardening of the mremap function was applied
to prevent a potential local denial of service attack.

The low latency patch applied in previous kernels has also been found
to cause stability problems under certain conditions. It has been
disabled in this update whilst further investigation occurs.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-April/000102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e034338"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/14");
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
if (rpm_check(release:"FC1", reference:"kernel-2.4.22-1.2179.nptl")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"kernel-BOOT-2.4.22-1.2179.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-debuginfo-2.4.22-1.2179.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-doc-2.4.22-1.2179.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-smp-2.4.22-1.2179.nptl")) flag++;
if (rpm_check(release:"FC1", reference:"kernel-source-2.4.22-1.2179.nptl")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-debuginfo / kernel-doc / kernel-smp / etc");
}
