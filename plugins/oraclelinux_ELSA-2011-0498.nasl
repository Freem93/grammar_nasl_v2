#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0498 and 
# Oracle Linux Security Advisory ELSA-2011-0498 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68273);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2010-4250", "CVE-2010-4565", "CVE-2010-4649", "CVE-2011-0006", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1019", "CVE-2011-1044", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1573");
  script_bugtraq_id(46417, 46419, 46488, 46557, 46616, 46793, 47308, 47639, 47792);
  script_xref(name:"RHSA", value:"2011:0498");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2011-0498)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0498 :

Updated kernel packages that fix several security issues, various
bugs, and add an enhancement are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* An integer overflow flaw in ib_uverbs_poll_cq() could allow a local,
unprivileged user to cause a denial of service or escalate their
privileges. (CVE-2010-4649, Important)

* An integer signedness flaw in drm_modeset_ctl() could allow a local,
unprivileged user to cause a denial of service or escalate their
privileges. (CVE-2011-1013, Important)

* The Radeon GPU drivers in the Linux kernel were missing sanity
checks for the Anti Aliasing (AA) resolve register values which could
allow a local, unprivileged user to cause a denial of service or
escalate their privileges on systems using a graphics card from the
ATI Radeon R300, R400, or R500 family of cards. (CVE-2011-1016,
Important)

* A flaw in dccp_rcv_state_process() could allow a remote attacker to
cause a denial of service, even when the socket was already closed.
(CVE-2011-1093, Important)

* A flaw in the Linux kernel's Stream Control Transmission Protocol
(SCTP) implementation could allow a remote attacker to cause a denial
of service if the sysctl 'net.sctp.addip_enable' and 'auth_enable'
variables were turned on (they are off by default). (CVE-2011-1573,
Important)

* A memory leak in the inotify_init() system call. In some cases, it
could leak a group, which could allow a local, unprivileged user to
eventually cause a denial of service. (CVE-2010-4250, Moderate)

* A missing validation of a null-terminated string data structure
element in bnep_sock_ioctl() could allow a local user to cause an
information leak or a denial of service. (CVE-2011-1079, Moderate)

* An information leak in bcm_connect() in the Controller Area Network
(CAN) Broadcast Manager implementation could allow a local,
unprivileged user to leak kernel mode addresses in
'/proc/net/can-bcm'. (CVE-2010-4565, Low)

* A flaw was found in the Linux kernel's Integrity Measurement
Architecture (IMA) implementation. When SELinux was disabled, adding
an IMA rule which was supposed to be processed by SELinux would cause
ima_match_rules() to always succeed, ignoring any remaining rules.
(CVE-2011-0006, Low)

* A missing initialization flaw in the XFS file system implementation
could lead to an information leak. (CVE-2011-0711, Low)

* Buffer overflow flaws in snd_usb_caiaq_audio_init() and
snd_usb_caiaq_midi_init() could allow a local, unprivileged user with
access to a Native Instruments USB audio device to cause a denial of
service or escalate their privileges. (CVE-2011-0712, Low)

* The start_code and end_code values in '/proc/[pid]/stat' were not
protected. In certain scenarios, this flaw could be used to defeat
Address Space Layout Randomization (ASLR). (CVE-2011-0726, Low)

* A flaw in dev_load() could allow a local user who has the
CAP_NET_ADMIN capability to load arbitrary modules from
'/lib/modules/', instead of only netdev modules. (CVE-2011-1019, Low)

* A flaw in ib_uverbs_poll_cq() could allow a local, unprivileged user
to cause an information leak. (CVE-2011-1044, Low)

* A missing validation of a null-terminated string data structure
element in do_replace() could allow a local user who has the
CAP_NET_ADMIN capability to cause an information leak. (CVE-2011-1080,
Low)

Red Hat would like to thank Vegard Nossum for reporting CVE-2010-4250;
Vasiliy Kulikov for reporting CVE-2011-1079, CVE-2011-1019, and
CVE-2011-1080; Dan Rosenberg for reporting CVE-2010-4565 and
CVE-2011-0711; Rafael Dominguez Vega for reporting CVE-2011-0712; and
Kees Cook for reporting CVE-2011-0726.

This update also fixes various bugs and adds an enhancement.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

Users should upgrade to these updated packages, which contain
backported patches to resolve these issues, and fix the bugs and add
the enhancement noted in the Technical Notes. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-May/002136.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-71.29.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-71.29.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-71.29.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-71.29.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-71.29.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-71.29.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-71.29.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
