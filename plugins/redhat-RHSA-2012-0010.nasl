#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0010. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76635);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:04:20 $");

  script_cve_id("CVE-2011-1162", "CVE-2011-2494", "CVE-2011-2723", "CVE-2011-2898", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-3637", "CVE-2011-4081", "CVE-2011-4110", "CVE-2011-4132", "CVE-2011-4326");
  script_bugtraq_id(48929, 48986, 49289, 49295, 49527, 49626, 49629, 50314, 50366, 50663, 50751, 50755, 50764);
  script_osvdb_id(74138, 74910, 75580, 75716, 76176, 76259, 76639, 76796, 77092, 77292, 77293, 77295, 77450, 78302);
  script_xref(name:"RHSA", value:"2012:0010");

  script_name(english:"RHEL 6 : MRG (RHSA-2012:0010)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel-rt packages that fix several security issues and two
bugs are now available for Red Hat Enterprise MRG 2.0.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A malicious CIFS (Common Internet File System) server could send a
specially crafted response to a directory read request that would
result in a denial of service or privilege escalation on a system that
has a CIFS share mounted. (CVE-2011-3191, Important)

* The way fragmented IPv6 UDP datagrams over the bridge with UDP
Fragmentation Offload (UFO) functionality on were handled could allow
a remote attacker to cause a denial of service. (CVE-2011-4326,
Important)

* GRO (Generic Receive Offload) fields could be left in an
inconsistent state. An attacker on the local network could use this
flaw to cause a denial of service. GRO is enabled by default in all
network drivers that support it. (CVE-2011-2723, Moderate)

* IPv4 and IPv6 protocol sequence number and fragment ID generation
could allow a man-in-the-middle attacker to inject packets and
possibly hijack connections. Protocol sequence numbers and fragment
IDs are now more random. (CVE-2011-3188, Moderate)

* A flaw in the FUSE (Filesystem in Userspace) implementation could
allow a local user in the fuse group who has access to mount a FUSE
file system to cause a denial of service. (CVE-2011-3353, Moderate)

* A flaw in the b43 driver. If a system had an active wireless
interface that uses the b43 driver, an attacker able to send a
specially crafted frame to that interface could cause a denial of
service. (CVE-2011-3359, Moderate)

* A flaw in the way CIFS shares with DFS referrals at their root were
handled could allow an attacker on the local network, who is able to
deploy a malicious CIFS server, to create a CIFS network share that,
when mounted, would cause the client system to crash. (CVE-2011-3363,
Moderate)

* A flaw in the m_stop() implementation could allow a local,
unprivileged user to trigger a denial of service. (CVE-2011-3637,
Moderate)

* Flaws in ghash_update() and ghash_final() could allow a local,
unprivileged user to cause a denial of service. (CVE-2011-4081,
Moderate)

* A flaw in the key management facility could allow a local,
unprivileged user to cause a denial of service via the keyctl utility.
(CVE-2011-4110, Moderate)

* A flaw in the Journaling Block Device (JBD) could allow a local
attacker to crash the system by mounting a specially crafted ext3 or
ext4 disk. (CVE-2011-4132, Moderate)

* A flaw in the way memory containing security-related data was
handled in tpm_read() could allow a local, unprivileged user to read
the results of a previously run TPM command. (CVE-2011-1162, Low)

* I/O statistics from the taskstats subsystem could be read without
any restrictions, which could allow a local, unprivileged user to
gather confidential information, such as the length of a password used
in a process. (CVE-2011-2494, Low)

* Flaws in tpacket_rcv() and packet_recvmsg() could allow a local,
unprivileged user to leak information to user-space. (CVE-2011-2898,
Low)

Red Hat would like to thank Darren Lavender for reporting
CVE-2011-3191; Brent Meshier for reporting CVE-2011-2723; Dan Kaminsky
for reporting CVE-2011-3188; Yogesh Sharma for reporting
CVE-2011-3363; Nick Bowler for reporting CVE-2011-4081; Peter Huewe
for reporting CVE-2011-1162; and Vasiliy Kulikov of Openwall for
reporting CVE-2011-2494.

This update also fixes the following bugs :

* Previously, a mismatch in the build-id of the kernel-rt and the one
in the related debuginfo package caused failures in SystemTap and
perf. (BZ#768413)

* IBM x3650m3 systems were not able to boot the MRG Realtime kernel
because they require a pmcraid driver that was not available. The
pmcraid driver is included in this update. (BZ#753992)

Users should upgrade to these updated packages, which correct these
issues. The system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2723.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2898.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3359.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3363.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3637.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4326.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0010.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0010";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-doc-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-2.6.33.9-rt31.79.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-2.6.33.9-rt31.79.el6rt")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
