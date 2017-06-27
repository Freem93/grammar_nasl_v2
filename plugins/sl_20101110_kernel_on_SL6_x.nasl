#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60893);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/15 16:37:17 $");

  script_cve_id("CVE-2010-2803", "CVE-2010-2955", "CVE-2010-2962", "CVE-2010-3079", "CVE-2010-3081", "CVE-2010-3084", "CVE-2010-3301", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3698", "CVE-2010-3705", "CVE-2010-3904");

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
"This update fixes the following security issues :

  - Missing sanity checks in the Intel i915 driver in the
    Linux kernel could allow a local, unprivileged user to
    escalate their privileges. (CVE-2010-2962, Important)

  - compat_alloc_user_space() in the Linux kernel 32/64-bit
    compatibility layer implementation was missing sanity
    checks. This function could be abused in other areas of
    the Linux kernel if its length argument can be
    controlled from user-space. On 64-bit systems, a local,
    unprivileged user could use this flaw to escalate their
    privileges. (CVE-2010-3081, Important)

  - A buffer overflow flaw in niu_get_ethtool_tcam_all() in
    the niu Ethernet driver in the Linux kernel, could allow
    a local user to cause a denial of service or escalate
    their privileges. (CVE-2010-3084, Important)

  - A flaw in the IA32 system call emulation provided in
    64-bit Linux kernels could allow a local user to
    escalate their privileges. (CVE-2010-3301, Important)

  - A flaw in sctp_packet_config() in the Linux kernel's
    Stream Control Transmission Protocol (SCTP)
    implementation could allow a remote attacker to cause a
    denial of service. (CVE-2010-3432, Important)

  - A missing integer overflow check in snd_ctl_new() in the
    Linux kernel's sound subsystem could allow a local,
    unprivileged user on a 32-bit system to cause a denial
    of service or escalate their privileges. (CVE-2010-3442,
    Important)

  - A flaw was found in sctp_auth_asoc_get_hmac() in the
    Linux kernel's SCTP implementation. When iterating
    through the hmac_ids array, it did not reset the last id
    element if it was out of range. This could allow a
    remote attacker to cause a denial of service.
    (CVE-2010-3705, Important)

  - A function in the Linux kernel's Reliable Datagram
    Sockets (RDS) protocol implementation was missing sanity
    checks, which could allow a local, unprivileged user to
    escalate their privileges. (CVE-2010-3904, Important)

  - A flaw in drm_ioctl() in the Linux kernel's Direct
    Rendering Manager (DRM) implementation could allow a
    local, unprivileged user to cause an information leak.
    (CVE-2010-2803, Moderate)

  - It was found that wireless drivers might not always
    clear allocated buffers when handling a driver-specific
    IOCTL information request. A local user could trigger
    this flaw to cause an information leak. (CVE-2010-2955,
    Moderate)

  - A NULL pointer dereference flaw in ftrace_regex_lseek()
    in the Linux kernel's ftrace implementation could allow
    a local, unprivileged user to cause a denial of service.
    Note: The debugfs file system must be mounted locally to
    exploit this issue. It is not mounted by default.
    (CVE-2010-3079, Moderate)

  - A flaw in the Linux kernel's packet writing driver could
    be triggered via the PKT_CTRL_CMD_STATUS IOCTL request,
    possibly allowing a local, unprivileged user with access
    to '/dev/pktcdvd/control' to cause an information leak.
    Note: By default, only users in the cdrom group have
    access to '/dev/pktcdvd/control'. (CVE-2010-3437,
    Moderate)

  - A flaw was found in the way KVM (Kernel-based Virtual
    Machine) handled the reloading of fs and gs segment
    registers when they had invalid selectors. A privileged
    host user with access to '/dev/kvm' could use this flaw
    to crash the host. (CVE-2010-3698, Moderate)

This update also fixes several bugs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=969
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fa9df38"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-71.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-71.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-71.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-71.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-71.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-71.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-71.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-71.7.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
