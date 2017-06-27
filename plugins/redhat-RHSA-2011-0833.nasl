#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0833. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54925);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-0726", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1163", "CVE-2011-1166", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1577", "CVE-2011-1763");
  script_bugtraq_id(46616, 46793, 46878, 46919, 47185, 47343, 47791, 48048);
  script_xref(name:"RHSA", value:"2011:0833");

  script_name(english:"RHEL 5 : kernel (RHSA-2011:0833)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw in the dccp_rcv_state_process() function could allow a remote
attacker to cause a denial of service, even when the socket was
already closed. (CVE-2011-1093, Important)

* Multiple buffer overflow flaws were found in the Linux kernel's
Management Module Support for Message Passing Technology (MPT) based
controllers. A local, unprivileged user could use these flaws to cause
a denial of service, an information leak, or escalate their
privileges. (CVE-2011-1494, CVE-2011-1495, Important)

* A missing validation of a null-terminated string data structure
element in the bnep_sock_ioctl() function could allow a local user to
cause an information leak or a denial of service. (CVE-2011-1079,
Moderate)

* Missing error checking in the way page tables were handled in the
Xen hypervisor implementation could allow a privileged guest user to
cause the host, and the guests, to lock up. (CVE-2011-1166, Moderate)

* A flaw was found in the way the Xen hypervisor implementation
checked for the upper boundary when getting a new event channel port.
A privileged guest user could use this flaw to cause a denial of
service or escalate their privileges. (CVE-2011-1763, Moderate)

* The start_code and end_code values in '/proc/[pid]/stat' were not
protected. In certain scenarios, this flaw could be used to defeat
Address Space Layout Randomization (ASLR). (CVE-2011-0726, Low)

* A missing initialization flaw in the sco_sock_getsockopt() function
could allow a local, unprivileged user to cause an information leak.
(CVE-2011-1078, Low)

* A missing validation of a null-terminated string data structure
element in the do_replace() function could allow a local user who has
the CAP_NET_ADMIN capability to cause an information leak.
(CVE-2011-1080, Low)

* A buffer overflow flaw in the DEC Alpha OSF partition implementation
in the Linux kernel could allow a local attacker to cause an
information leak by mounting a disk that contains specially crafted
partition tables. (CVE-2011-1163, Low)

* Missing validations of null-terminated string data structure
elements in the do_replace(), compat_do_replace(), do_ipt_get_ctl(),
do_ip6t_get_ctl(), and do_arpt_get_ctl() functions could allow a local
user who has the CAP_NET_ADMIN capability to cause an information
leak. (CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, Low)

* A heap overflow flaw in the Linux kernel's EFI GUID Partition Table
(GPT) implementation could allow a local attacker to cause a denial of
service by mounting a disk that contains specially crafted partition
tables. (CVE-2011-1577, Low)

Red Hat would like to thank Dan Rosenberg for reporting CVE-2011-1494
and CVE-2011-1495; Vasiliy Kulikov for reporting CVE-2011-1079,
CVE-2011-1078, CVE-2011-1080, CVE-2011-1170, CVE-2011-1171, and
CVE-2011-1172; Kees Cook for reporting CVE-2011-0726; and Timo Warns
for reporting CVE-2011-1163 and CVE-2011-1577.

This update also fixes several bugs. Documentation for these bug fixes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0726.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1166.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1763.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0833.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0833";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-debug-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"kernel-doc-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"kernel-headers-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-headers-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-headers-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kernel-xen-devel-2.6.18-238.12.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-238.12.1.el5")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
  }
}
