#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1565. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85705);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2014-9715", "CVE-2015-2666", "CVE-2015-2922", "CVE-2015-3636");
  script_osvdb_id(119873, 120282, 120540, 121578);
  script_xref(name:"RHSA", value:"2015:1565");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2015:1565)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel-rt packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

* An integer overflow flaw was found in the way the Linux kernel's
netfilter connection tracking implementation loaded extensions. An
attacker on a local network could potentially send a sequence of
specially crafted packets that would initiate the loading of a large
number of extensions, causing the targeted system in that network to
crash. (CVE-2014-9715, Moderate)

* A stack-based buffer overflow flaw was found in the Linux kernel's
early load microcode functionality. On a system with UEFI Secure Boot
enabled, a local, privileged user could use this flaw to increase
their privileges to the kernel (ring0) level, bypassing intended
restrictions in place. (CVE-2015-2666, Moderate)

* It was found that the Linux kernel's ping socket implementation did
not properly handle socket unhashing during spurious disconnects,
which could lead to a use-after-free flaw. On x86-64 architecture
systems, a local user able to create ping sockets could use this flaw
to crash the system. On non-x86-64 architecture systems, a local user
able to create ping sockets could use this flaw to escalate their
privileges on the system. (CVE-2015-3636, Moderate)

* It was found that the Linux kernel's TCP/IP protocol suite
implementation for IPv6 allowed the Hop Limit value to be set to a
smaller value than the default one. An attacker on a local network
could use this flaw to prevent systems on that network from sending or
receiving network packets. (CVE-2015-2922, Low)

Red Hat would like to thank Nathan Hoad for reporting the
CVE-2014-9715 issue.

The kernel-rt packages have been upgraded to version 3.10.0-229.11.1,
which provides a number of bug fixes and enhancements over the
previous version, including :

* drbg: Add stdrng alias and increase priority

* seqiv / eseqiv / chainiv: Move IV seeding into init function

* ipv4: kABI fix for 0bbf87d backport

* ipv4: Convert ipv4.ip_local_port_range to be per netns

* libceph: tcp_nodelay support

* ipr: Increase default adapter init stage change timeout

* fix use-after-free bug in usb_hcd_unlink_urb()

* libceph: fix double __remove_osd() problem

* ext4: fix data corruption caused by unwritten and delayed extents

* sunrpc: Add missing support for RPC_CLNT_CREATE_NO_RETRANS_TIMEOUT

* nfs: Fixing lease renewal (Benjamin Coddington)

* control hard lockup detection default

* Fix print-once on enable

* watchdog: update watchdog_thresh properly and watchdog attributes
atomically

* module: Call module notifier on failure after complete_formation()

(BZ#1234470)

This update also fixes the following bugs :

* The megasas driver used the smp_processor_id() function within a
preemptible context, which caused warning messages to be returned to
the console. The function has been changed to raw_smp_processor_id()
so that a lock is held while getting the processor ID. As a result,
correct operations are now allowed without any console warnings being
produced. (BZ#1235304)

* In the NFSv4 file system, non-standard usage of the
write_seqcount_{begin,end}() functions were used, which caused the
realtime code to try to sleep while locks were held. As a consequence,
the 'scheduling while atomic' error messages were returned. The
underlying source code has been modified to use the
__write_seqcount_{begin,end}() functions that do not hold any locks,
allowing correct execution of realtime. (BZ#1235301)

All kernel-rt users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements. The system must
be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9715.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2666.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3636.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1565";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-devel-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-rt-doc-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.0-229.11.1.rt56.141.11.el7_1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
