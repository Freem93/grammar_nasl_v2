#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1778 and 
# CentOS Errata and Security Advisory 2015:1778 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(86511);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/03 14:41:28 $");

  script_cve_id("CVE-2014-9585", "CVE-2015-0275", "CVE-2015-1333", "CVE-2015-3212", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366");
  script_osvdb_id(116910, 118665, 123637, 123996, 124240, 125430);
  script_xref(name:"RHSA", value:"2015:1778");

  script_name(english:"CentOS 7 : kernel (CESA-2015:1778)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the kernel's implementation of the Berkeley
Packet Filter (BPF). A local attacker could craft BPF code to crash
the system by creating a situation in which the JIT compiler would
fail to correctly optimize the JIT image on the last pass. This would
lead to the CPU executing instructions that were not part of the JIT
code. (CVE-2015-4700, Important)

* Two flaws were found in the way the Linux kernel's networking
implementation handled UDP packets with incorrect checksum values. A
remote attacker could potentially use these flaws to trigger an
infinite loop in the kernel, resulting in a denial of service on the
system, or cause a denial of service in applications using the edge
triggered epoll functionality. (CVE-2015-5364, CVE-2015-5366,
Important)

* A flaw was found in the way the Linux kernel's ext4 file system
handled the 'page size > block size' condition when the fallocate zero
range functionality was used. A local attacker could use this flaw to
crash the system. (CVE-2015-0275, Moderate)

* It was found that the Linux kernel's keyring implementation would
leak memory when adding a key to a keyring via the add_key() function.
A local attacker could use this flaw to exhaust all available memory
on the system. (CVE-2015-1333, Moderate)

* A race condition flaw was found in the way the Linux kernel's SCTP
implementation handled Address Configuration lists when performing
Address Configuration Change (ASCONF). A local attacker could use this
flaw to crash the system via a race condition triggered by setting
certain ASCONF options on a socket. (CVE-2015-3212, Moderate)

* An information leak flaw was found in the way the Linux kernel's
Virtual Dynamic Shared Object (vDSO) implementation performed address
randomization. A local, unprivileged user could use this flaw to leak
kernel memory addresses to user-space. (CVE-2014-9585, Low)

Red Hat would like to thank Daniel Borkmann for reporting
CVE-2015-4700, and Canonical for reporting the CVE-2015-1333 issue.
The CVE-2015-0275 issue was discovered by Xiong Zhou of Red Hat, and
the CVE-2015-3212 issue was discovered by Ji Jianwen of Red Hat
Engineering.

This update also fixes several bugs. Refer to the following
Knowledgebase article for further information :

https://access.redhat.com/articles/1614563

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed59be41"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-229.14.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-229.14.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
