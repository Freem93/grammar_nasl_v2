#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1490. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76669);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-0343", "CVE-2013-2888", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-4299", "CVE-2013-4343", "CVE-2013-4345", "CVE-2013-4348", "CVE-2013-4350", "CVE-2013-4387");
  script_bugtraq_id(58795, 62043, 62045, 62048, 62049, 62050, 62360, 62405, 62696, 62740, 63183);
  script_osvdb_id(90811, 96767, 96771, 96772, 96774, 96775, 97236, 97569, 97888, 98017, 98634);
  script_xref(name:"RHSA", value:"2013:1490");

  script_name(english:"RHEL 6 : MRG (RHSA-2013:1490)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel-rt packages that fix multiple security issues and one
bug are now available for Red Hat Enterprise MRG 2.4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way IP packets with an Internet Header
Length (ihl) of zero were processed in the skb_flow_dissect() function
in the Linux kernel. A remote attacker could use this flaw to trigger
an infinite loop in the kernel, leading to a denial of service.
(CVE-2013-4348, Important)

* A flaw was found in the way the Linux kernel's IPv6 implementation
handled certain UDP packets when the UDP Fragmentation Offload (UFO)
feature was enabled. A remote attacker could use this flaw to crash
the system or, potentially, escalate their privileges on the system.
(CVE-2013-4387, Important)

* A flaw was found in the way the Linux kernel handled the creation of
temporary IPv6 addresses. If the IPv6 privacy extension was enabled
(/proc/sys/net/ipv6/conf/eth0/use_tempaddr set to '2'), an attacker on
the local network could disable IPv6 temporary address generation,
leading to a potential information disclosure. (CVE-2013-0343,
Moderate)

* A flaw was found in the way the Linux kernel handled HID (Human
Interface Device) reports with an out-of-bounds Report ID. An attacker
with physical access to the system could use this flaw to crash the
system or, potentially, escalate their privileges on the system.
(CVE-2013-2888, Moderate)

* Heap-based buffer overflow flaws were found in the way the
Pantherlord/GreenAsia game controller driver, the Logitech force
feedback drivers, and the Logitech Unifying receivers driver handled
HID reports. An attacker with physical access to the system could use
these flaws to crash the system or, potentially, escalate their
privileges on the system. (CVE-2013-2892, CVE-2013-2893,
CVE-2013-2895, Moderate)

* A NULL pointer dereference flaw was found in the way the N-Trig
touch screen driver handled HID reports. An attacker with physical
access to the system could use this flaw to crash the system,
resulting in a denial of service. (CVE-2013-2896, Moderate)

* An information leak flaw was found in the way the Linux kernel's
device mapper subsystem, under certain conditions, interpreted data
written to snapshot block devices. An attacker could use this flaw to
read data from disk blocks in free space, which are normally
inaccessible. (CVE-2013-4299, Moderate)

* A use-after-free flaw was found in the tun_set_iff() function in the
Universal TUN/TAP device driver implementation in the Linux kernel. A
privileged user could use this flaw to crash the system or,
potentially, further escalate their privileges on the system.
(CVE-2013-4343, Moderate)

* An off-by-one flaw was found in the way the ANSI CPRNG
implementation in the Linux kernel processed non-block size aligned
requests. This could lead to random numbers being generated with less
bits of entropy than expected when ANSI CPRNG was used.
(CVE-2013-4345, Moderate)

* A flaw was found in the way the Linux kernel's IPv6 SCTP
implementation interacted with the IPsec subsystem. This resulted in
unencrypted SCTP packets being sent over the network even though IPsec
encryption was enabled. An attacker able to inspect these SCTP packets
could use this flaw to obtain potentially sensitive information.
(CVE-2013-4350, Moderate)

Red Hat would like to thank Fujitsu for reporting CVE-2013-4299 and
Stephan Mueller for reporting CVE-2013-4345. The CVE-2013-4348 issue
was discovered by Jason Wang of Red Hat.

Bug fix :

* RoCE appeared to be supported in the MRG Realtime kernel even when
the required user space packages from the HPN channel were not
installed. The Realtime kernel now checks for the HPN channel packages
before exposing the RoCE interfaces. RoCE devices appear as plain
10GigE devices if the needed HPN channel user space packages are not
installed. (BZ#1012993)

Users should upgrade to these updated packages, which upgrade the
kernel-rt kernel to version kernel-rt-3.8.13-rt14, and correct these
issues. The system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0343.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2892.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2895.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4343.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4348.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4350.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4387.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1490.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mrg-rt-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/31");
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
  rhsa = "RHSA-2013:1490";
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

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-doc-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-3.8.13-rt14.25.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"mrg-rt-release-3.8.13-rt14.25.el6rt")) flag++;

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
