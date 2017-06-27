#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0883. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63986);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/18 18:39:01 $");

  script_cve_id("CVE-2010-3881", "CVE-2010-4251", "CVE-2010-4805", "CVE-2011-0999", "CVE-2011-1010", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1182", "CVE-2011-1494", "CVE-2011-1495");
  script_bugtraq_id(44666, 46442, 46492, 46630, 46637, 46766, 46878, 46919, 47003, 47185);
  script_xref(name:"RHSA", value:"2011:0883");

  script_name(english:"RHEL 6 : kernel (RHSA-2011:0883)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and three
bugs are now available for Red Hat Enterprise Linux 6.0 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update includes backported fixes for security issues. These
issues, except for CVE-2011-1182, only affected users of Red Hat
Enterprise Linux 6.0 Extended Update Support as they have already been
addressed for users of Red Hat Enterprise Linux 6 in the 6.1 update,
RHSA-2011:0542.

Security fixes :

* Buffer overflow flaws were found in the Linux kernel's Management
Module Support for Message Passing Technology (MPT) based controllers.
A local, unprivileged user could use these flaws to cause a denial of
service, an information leak, or escalate their privileges.
(CVE-2011-1494, CVE-2011-1495, Important)

* A flaw was found in the Linux kernel's networking subsystem. If the
number of packets received exceeded the receiver's buffer limit, they
were queued in a backlog, consuming memory, instead of being
discarded. A remote attacker could abuse this flaw to cause a denial
of service (out-of-memory condition). (CVE-2010-4251, CVE-2010-4805,
Moderate)

* A flaw was found in the Linux kernel's Transparent Huge Pages (THP)
implementation. A local, unprivileged user could abuse this flaw to
allow the user stack (when it is using huge pages) to grow and cause a
denial of service. (CVE-2011-0999, Moderate)

* A flaw in the Linux kernel's Event Poll (epoll) implementation could
allow a local, unprivileged user to cause a denial of service.
(CVE-2011-1082, Moderate)

* An inconsistency was found in the interaction between the Linux
kernel's method for allocating NFSv4 (Network File System version 4)
ACL data and the method by which it was freed. This inconsistency led
to a kernel panic which could be triggered by a local, unprivileged
user with files owned by said user on an NFSv4 share. (CVE-2011-1090,
Moderate)

* It was found that some structure padding and reserved fields in
certain data structures in KVM (Kernel-based Virtual Machine) were not
initialized properly before being copied to user-space. A privileged
host user with access to '/dev/kvm' could use this flaw to leak kernel
stack memory to user-space. (CVE-2010-3881, Low)

* A missing validation check was found in the Linux kernel's
mac_partition() implementation, used for supporting file systems
created on Mac OS operating systems. A local attacker could use this
flaw to cause a denial of service by mounting a disk that contains
specially crafted partitions. (CVE-2011-1010, Low)

* A buffer overflow flaw in the DEC Alpha OSF partition implementation
in the Linux kernel could allow a local attacker to cause an
information leak by mounting a disk that contains specially crafted
partition tables. (CVE-2011-1163, Low)

* Missing validations of null-terminated string data structure
elements in the do_replace(), compat_do_replace(), do_ipt_get_ctl(),
do_ip6t_get_ctl(), and do_arpt_get_ctl() functions could allow a local
user who has the CAP_NET_ADMIN capability to cause an information
leak. (CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, Low)

* A missing validation check was found in the Linux kernel's signals
implementation. A local, unprivileged user could use this flaw to send
signals via the sigqueueinfo system call, with the si_code set to
SI_TKILL and with spoofed process and user IDs, to other processes.
Note: This flaw does not allow existing permission checks to be
bypassed; signals can only be sent if your privileges allow you to
already do so. (CVE-2011-1182, Low)

Red Hat would like to thank Dan Rosenberg for reporting CVE-2011-1494
and CVE-2011-1495; Nelson Elhage for reporting CVE-2011-1082; Vasiliy
Kulikov for reporting CVE-2010-3881, CVE-2011-1170, CVE-2011-1171, and
CVE-2011-1172; Timo Warns for reporting CVE-2011-1010 and
CVE-2011-1163; and Julien Tinnes of the Google Security Team for
reporting CVE-2011-1182.

This update also fixes three bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3881.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4251.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0999.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1082.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1170.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1171.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2011-0542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0883.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-71.31.1.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"perf-2.6.32-71.31.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
