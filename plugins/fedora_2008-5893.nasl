#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-5893.
#

include("compat.inc");

if (description)
{
  script_id(33404);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:21:53 $");

  script_cve_id("CVE-2008-2358", "CVE-2008-2750");
  script_bugtraq_id(29603, 29747);
  script_xref(name:"FEDORA", value:"2008-5893");

  script_name(english:"Fedora 9 : kernel-2.6.25.9-76.fc9 (2008-5893)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update kernel from version 2.6.25.6 to 2.6.25.9:
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.7
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.8
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.9
Security updates: CVE-2008-2750: The pppol2tp_recvmsg function in
drivers/net/pppol2tp.c in the Linux kernel 2.6 before 2.6.26-rc6
allows remote attackers to cause a denial of service (kernel heap
memory corruption and system crash) and possibly have unspecified
other impact via a crafted PPPOL2TP packet that results in a large
value for a certain length variable. CVE-2008-2358: The Datagram
Congestion Control Protocol (DCCP) subsystem in the Linux kernel
2.6.18, and probably other versions, does not properly check feature
lengths, which might allow remote attackers to execute arbitrary code,
related to an unspecified 'overflow.' Wireless driver updates: -
Upstream wireless fixes from 2008-06-27
(http://marc.info/?l=linux-wireless&m=121459423021061&w=2) - Upstream
wireless fixes from 2008-06-25 (http://marc.info/?l=linux-
wireless&m=121440912502527&w=2) - Upstream wireless updates from
2008-06-14 (http://marc.info/?l=linux-netdev&m=121346686508160&w=2) -
Upstream wireless fixes from 2008-06-09 (http://marc.info/?l=linux-
kernel&m=121304710726632&w=2) - Upstream wireless updates from
2008-06-09 (http://marc.info/?l=linux-netdev&m=121304710526613&w=2)
Bugs: 444694 - ALi Corporation M5253 P1394 OHCI 1.1 Controller driver
causing problems in kernels newer than 2.6.24.3-50 452595 - Problem
with SATA/IDE on Abit AN52 449080 - Rsync cannot copy to a vfat
partition on kernel 2.6.25 with -p or -a options 449909 - User Mode
Linux (UML) broken on Fedora 9 452111 - CVE-2008-2750 kernel: l2tp:
Fix potential memory corruption in pppol2tp-recvmsg() (Heap corruption
DoS) [F9] 449872 - [Patch] Bluetooth keyboard not reconnecting after
powersave

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=linux-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=linux-netdev&m=121304710526613&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=linux-netdev&m=121346686508160&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=linux-wireless&m=121459423021061&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=444694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=449080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=449872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=449909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452595"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/011962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5b9acba"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a593745"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"kernel-2.6.25.9-76.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
