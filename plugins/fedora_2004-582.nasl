#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-582.
#

include("compat.inc");

if (description)
{
  script_id(16107);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_xref(name:"FEDORA", value:"2004-582");

  script_name(english:"Fedora Core 3 : kernel-2.6.9-1.724_FC3 (2004-582)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A large change over previous kernels has been made. The 4G:4G memory
split patch has been dropped, and Fedora kernels now revert back to
the upstream 3G:1G kernel/userspace split.

A number of security fixes are present in this update.

CVE-2004-1016: Paul Starzetz discovered a buffer overflow
vulnerability in the '__scm_send' function which handles the sending
of UDP network packets. A wrong validity check of the cmsghdr
structure allowed a local attacker to modify kernel memory, thus
causing an endless loop (Denial of Service) or possibly even root
privilege escalation.

CVE-2004-1017: Alan Cox reported two potential buffer overflows with
the io_edgeport driver.

CVE-2004-1068: A race condition was discovered in the handling of
AF_UNIX network packets. This reportedly allowed local users to modify
arbitrary kernel memory, facilitating privilege escalation, or
possibly allowing code execution in the context of the kernel.

CVE-2004-1137: Paul Starzetz discovered several flaws in the IGMP
handling code. This allowed users to provoke a Denial of Service, read
kernel memory, and execute arbitrary code with root privileges. This
flaw is also exploitable remotely if an application has bound a
multicast socket.

CVE-2004-1151: Jeremy Fitzhardinge discovered two buffer overflows in
the sys32_ni_syscall() and sys32_vm86_warning() functions. This could
possibly be exploited to overwrite kernel memory with
attacker-supplied code and cause root privilege escalation.

NO-CAN-ASSIGNED :

  - Fix memory leak in ip_conntrack_ftp (local DoS)

    - Do not leak IP options. (local DoS)

    - fix missing security_*() check in net/compat.c

    - ia64/x86_64/s390 overlapping vma fix

    - Fix bugs with SOCK_SEQPACKET AF_UNIX sockets

    - Make sure VC resizing fits in s16. Georgi Guninski
      reported a buffer overflow with vc_resize().

  - Clear ebp on sysenter return. A small information leak
    was found by Brad Spengler.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-January/000545.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc362619"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/04");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"kernel-2.6.9-1.724_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-debuginfo-2.6.9-1.724_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-doc-2.6.9-1.724_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-smp-2.6.9-1.724_FC3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-doc / kernel-smp");
}
