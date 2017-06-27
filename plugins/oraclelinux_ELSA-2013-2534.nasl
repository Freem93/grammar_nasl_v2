#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-2534.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68856);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2012-4542", "CVE-2012-5517", "CVE-2012-6537", "CVE-2012-6542", "CVE-2012-6546", "CVE-2012-6547", "CVE-2013-0349", "CVE-2013-0871", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1798", "CVE-2013-1826", "CVE-2013-1827", "CVE-2013-1860", "CVE-2013-1929", "CVE-2013-1943");
  script_bugtraq_id(56527, 57986, 58088, 58112, 58202, 58368, 58381, 58383, 58510, 58604, 58607, 58908, 58977, 58989, 58992, 58996, 60466);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2013-2534)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:


[2.6.32-400.29.1.el6uek]
- KVM: add missing void __user COPYING CREDITS Documentation Kbuild 
MAINTAINERS Makefile README REPORTING-BUGS arch block crypto drivers 
firmware fs include init ipc kernel lib mm net samples scripts security 
sound tools uek-rpm usr virt cast to access_ok() call (Heiko Carstens) 
[Orabug: 16941620] {CVE-2013-1943}
- KVM: Validate userspace_addr of memslot when registered (Takuya 
Yoshikawa) [Orabug: 16941620] {CVE-2013-1943}

[2.6.32-400.28.1.el6uek]
- do_add_mount()/umount -l races (Jerry Snitselaar) [Orabug: 16311974]
- tg3: fix length overflow in VPD firmware parsing (Kees Cook) [Orabug: 
16837019] {CVE-2013-1929}
- USB: cdc-wdm: fix buffer overflow (Oliver Neukum) [Orabug: 16837003] 
{CVE-2013-1860}
- bonding: emit event when bonding changes MAC (Weiping Pan) [Orabug: 
16579025]
- sched: Fix ancient race in do_exit() (Joe Jin)
- open debug in page_move_anon_rmap by default. (Xiaowei.Hu) [Orabug: 
14046035]
- block: default SCSI command filter does not accomodate commands 
overlap across device classes (Jamie Iles) [Orabug: 16387136] 
{CVE-2012-4542}
- vma_adjust: fix the copying of anon_vma chains (Linus Torvalds) 
[Orabug: 14046035]
- xen-netfront: delay gARP until backend switches to Connected (Laszlo 
Ersek) [Orabug: 16182568]
- svcrpc: don't hold sv_lock over svc_xprt_put() (J. Bruce Fields) 
[Orabug: 16032824]
- mm/hotplug: correctly add new zone to all other nodes' zone lists 
(Jiang Liu) [Orabug: 16603569] {CVE-2012-5517}
- ptrace: ptrace_resume() shouldn't wake up !TASK_TRACED thread (Oleg 
Nesterov) [Orabug: 16405868] {CVE-2013-0871}
- ptrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL 
(Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}
- ptrace: introduce signal_wake_up_state() and ptrace_signal_wake_up() 
(Oleg Nesterov) [Orabug: 16405868] {CVE-2013-0871}
- Bluetooth: Fix incorrect strncpy() in hidp_setup_hid() (Anderson 
Lizardo) [Orabug: 16711062] {CVE-2013-0349}
- dccp: check ccid before dereferencing (Mathias Krause) [Orabug: 
16711040] {CVE-2013-1827}
- USB: io_ti: Fix NULL dereference in chase_port() (Wolfgang Frisch) 
[Orabug: 16425435] {CVE-2013-1774}
- keys: fix race with concurrent install_user_keyrings() (David Howells) 
[Orabug: 16493369] {CVE-2013-1792}
- KVM: Fix bounds checking in ioapic indirect register reads 
(CVE-2013-1798) (Andy Honig) [Orabug: 16710937] {CVE-2013-1798}
- KVM: x86: fix for buffer overflow in handling of MSR_KVM_SYSTEM_TIME 
(CVE-2013-1796) (Jerry Snitselaar) [Orabug: 16710794] {CVE-2013-1796}

[2.6.32-400.27.1.el6uek]
- net/tun: fix ioctl() based info leaks (Mathias Krause) [Orabug: 
16675501] {CVE-2012-6547}
- atm: fix info leak via getsockname() (Mathias Krause) [Orabug: 
16675501] {CVE-2012-6546}
- atm: fix info leak in getsockopt(SO_ATMPVC) (Mathias Krause) [Orabug: 
16675501] {CVE-2012-6546}
- xfrm_user: fix info leak in copy_to_user_tmpl() (Mathias Krause) 
[Orabug: 16675501] {CVE-2012-6537}
- xfrm_user: fix info leak in copy_to_user_policy() (Mathias Krause) 
[Orabug: 16675501] {CVE-2012-6537}
- xfrm_user: fix info leak in copy_to_user_state() (Mathias Krause) 
[Orabug: 16675501] {CVE-2013-6537}
- xfrm_user: return error pointer instead of NULL #2 (Mathias Krause) 
[Orabug: 16675501] {CVE-2013-1826}
- xfrm_user: return error pointer instead of NULL (Mathias Krause) 
[Orabug: 16675501] {CVE-2013-1826}
- llc: fix info leak via getsockname() (Mathias Krause) [Orabug: 
16675501] {CVE-2012-6542}
- x86/mm: Check if PUD is large when validating a kernel address (Mel 
Gorman) [Orabug: 14251997]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-June/003512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-June/003513.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.29.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.29.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.29.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mlnx_en-2.6.32-400.29.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.29.1.el5uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.29.1.el5uekdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.29.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-400.29.1.el6uekdebug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.32-400.29.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.32-400.29.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.32-400.29.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.32-400.29.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.32-400.29.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.32-400.29.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL5", reference:"kernel-uek-headers-2.6.32-400.29.1.el5uek")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-400.29.1.el5uek-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"mlnx_en-2.6.32-400.29.1.el5uekdebug-1.5.7-2")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-400.29.1.el5uek-1.5.1-4.0.58")) flag++;
if (rpm_check(release:"EL5", reference:"ofa-2.6.32-400.29.1.el5uekdebug-1.5.1-4.0.58")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.32-400.29.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.32-400.29.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.32-400.29.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.32-400.29.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.32-400.29.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.32-400.29.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-uek-headers-2.6.32-400.29.1.el6uek")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-400.29.1.el6uek-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"mlnx_en-2.6.32-400.29.1.el6uekdebug-1.5.7-0.1")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-400.29.1.el6uek-1.5.1-4.0.58")) flag++;
if (rpm_check(release:"EL6", reference:"ofa-2.6.32-400.29.1.el6uekdebug-1.5.1-4.0.58")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
