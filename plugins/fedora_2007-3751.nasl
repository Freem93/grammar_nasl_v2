#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-3751.
#

include("compat.inc");

if (description)
{
  script_id(29264);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 21:54:56 $");

  script_cve_id("CVE-2007-5500", "CVE-2007-5501");
  script_bugtraq_id(26474, 26477);
  script_xref(name:"FEDORA", value:"2007-3751");

  script_name(english:"Fedora 7 : kernel-2.6.23.8-34.fc7 (2007-3751)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to kernel 2.6.23.9-rc1:
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.2
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.3
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.4
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.5
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.6
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.7
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.8

CVE-2007-5501: The tcp_sacktag_write_queue function in
net/ipv4/tcp_input.c in Linux kernel 2.6.24-rc2 and earlier allows
remote attackers to cause a denial of service (crash) via crafted ACK
responses that trigger a NULL pointer dereference.

CVE-2007-5500: The wait_task_stopped function in the Linux kernel
before 2.6.23.8 checks a TASK_TRACED bit instead of an exit_state
value, which allows local users to cause a denial of service (machine
crash) via unspecified vectors.

Additional fixes: Major wireless updates. Fix oops in netfilter NAT
module (#259501) libata: fix resume on some systems libata: fix
pata_serverworks with some drive combinations Initial FireWire OHCI
1.0 Isochronous Receive support (#344851) Disable USB autosuspend by
default. Fix oops in CIFS when mounting a filesystem a second time.
Restore platform module autoloading, e.g. pcspkr. Fix failure to boot
on 486DX4 (and possibily other CPUs.)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=259501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=344851"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67eef7de"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"kernel-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-PAE-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-PAE-debug-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-PAE-debug-debuginfo-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-PAE-debug-devel-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-PAE-debuginfo-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-PAE-devel-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-debug-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-debug-debuginfo-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-debug-devel-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-debuginfo-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-debuginfo-common-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-devel-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-doc-2.6.23.8-34.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kernel-headers-2.6.23.8-34.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debug / kernel-PAE-debug-debuginfo / etc");
}
