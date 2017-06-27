#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2003-002.
#

include("compat.inc");

if (description)
{
  script_id(13661);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:09:30 $");

  script_cve_id("CVE-2003-0859");
  script_xref(name:"FEDORA", value:"2003-002");

  script_name(english:"Fedora Core 1 : glibc-2.3.2-101.1 (2003-002)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Herbert Xu reported that various applications can accept spoofed
messages sent on the kernel netlink interface by other users on the
local machine. This could lead to a local denial of service attack.
The glibc function getifaddrs uses netlink and could therefore be
vulnerable to this issue. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2003-0859 to this
issue.

In addition to this this update fixes a couple of bugs.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2003-November/000004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1510b84b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nptl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/14");
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
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-common-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-debug-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-debuginfo-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-debuginfo-common-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-devel-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-headers-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-profile-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"glibc-utils-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"nptl-devel-2.3.2-101.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"nscd-2.3.2-101.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debug / glibc-debuginfo / etc");
}
