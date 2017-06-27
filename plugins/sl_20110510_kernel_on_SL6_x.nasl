#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61035);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-4250", "CVE-2010-4565", "CVE-2010-4649", "CVE-2011-0006", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1019", "CVE-2011-1044", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1573");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fixes :

  - An integer overflow flaw in ib_uverbs_poll_cq() could
    allow a local, unprivileged user to cause a denial of
    service or escalate their privileges. (CVE-2010-4649,
    Important)

  - An integer signedness flaw in drm_modeset_ctl() could
    allow a local, unprivileged user to cause a denial of
    service or escalate their privileges. (CVE-2011-1013,
    Important)

  - The Radeon GPU drivers in the Linux kernel were missing
    sanity checks for the Anti Aliasing (AA) resolve
    register values which could allow a local, unprivileged
    user to cause a denial of service or escalate their
    privileges on systems using a graphics card from the ATI
    Radeon R300, R400, or R500 family of cards.
    (CVE-2011-1016, Important)

  - A flaw in dccp_rcv_state_process() could allow a remote
    attacker to cause a denial of service, even when the
    socket was already closed. (CVE-2011-1093, Important)

  - A flaw in the Linux kernel's Stream Control Transmission
    Protocol (SCTP) implementation could allow a remote
    attacker to cause a denial of service if the sysctl
    'net.sctp.addip_enable' and 'auth_enable' variables were
    turned on (they are off by default). (CVE-2011-1573,
    Important)

  - A memory leak in the inotify_init() system call. In some
    cases, it could leak a group, which could allow a local,
    unprivileged user to eventually cause a denial of
    service. (CVE-2010-4250, Moderate)

  - A missing validation of a null-terminated string data
    structure element in bnep_sock_ioctl() could allow a
    local user to cause an information leak or a denial of
    service. (CVE-2011-1079, Moderate)

  - An information leak in bcm_connect() in the Controller
    Area Network (CAN) Broadcast Manager implementation
    could allow a local, unprivileged user to leak kernel
    mode addresses in '/proc/net/can-bcm'. (CVE-2010-4565,
    Low)

  - A flaw was found in the Linux kernel's Integrity
    Measurement Architecture (IMA) implementation. When
    SELinux was disabled, adding an IMA rule which was
    supposed to be processed by SELinux would cause
    ima_match_rules() to always succeed, ignoring any
    remaining rules. (CVE-2011-0006, Low)

  - A missing initialization flaw in the XFS file system
    implementation could lead to an information leak.
    (CVE-2011-0711, Low)

  - Buffer overflow flaws in snd_usb_caiaq_audio_init() and
    snd_usb_caiaq_midi_init() could allow a local,
    unprivileged user with access to a Native Instruments
    USB audio device to cause a denial of service or
    escalate their privileges. (CVE-2011-0712, Low)

  - The start_code and end_code values in '/proc/[pid]/stat'
    were not protected. In certain scenarios, this flaw
    could be used to defeat Address Space Layout
    Randomization (ASLR). (CVE-2011-0726, Low)

  - A flaw in dev_load() could allow a local user who has
    the CAP_NET_ADMIN capability to load arbitrary modules
    from '/lib/modules/', instead of only netdev modules.
    (CVE-2011-1019, Low)

  - A flaw in ib_uverbs_poll_cq() could allow a local,
    unprivileged user to cause an information leak.
    (CVE-2011-1044, Low)

  - A missing validation of a null-terminated string data
    structure element in do_replace() could allow a local
    user who has the CAP_NET_ADMIN capability to cause an
    information leak. (CVE-2011-1080, Low)

This update also fixes various bugs.

This update also adds an enhancement.

  - This update provides VLAN null tagging support (VLAN ID
    0 can be used in tags).

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1105&L=scientific-linux-errata&T=0&P=857
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14e371c1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-71.29.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-71.29.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-71.29.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-71.29.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-71.29.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-71.29.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-71.29.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-71.29.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
