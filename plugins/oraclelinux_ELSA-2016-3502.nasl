#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2016-3502.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87835);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/28 21:03:37 $");

  script_cve_id("CVE-2010-5313", "CVE-2013-7421", "CVE-2014-7842", "CVE-2014-9644", "CVE-2015-5307", "CVE-2015-7613", "CVE-2015-7872", "CVE-2015-8104");

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2016-3502)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[2.6.39-400.264.13.el6uek]
- KEYS: Don't permit request_key() to construct a new keyring (David 
Howells)  [Orabug: 22373449]  {CVE-2015-7872}

[2.6.39-400.264.12.el6uek]
- crypto: add missing crypto module aliases (Mathias Krause)  [Orabug: 
22249656]  {CVE-2013-7421} {CVE-2014-9644}
- crypto: include crypto- module prefix in template (Kees Cook) 
[Orabug: 22249656]  {CVE-2013-7421} {CVE-2014-9644}
- crypto: prefix module autoloading with 'crypto-' (Kees Cook)  [Orabug: 
22249656]  {CVE-2013-7421} {CVE-2014-9644}

[2.6.39-400.264.11.el6uek]
- KVM: x86: Don't report guest userspace emulation error to userspace 
(Nadav Amit)  [Orabug: 22249615]  {CVE-2010-5313} {CVE-2014-7842}

[2.6.39-400.264.9.el6uek]
- msg_unlock() in wrong spot after applying 'Initialize msg/shm IPC 
objects before doing ipc_addid()' (Chuck Anderson)  [Orabug: 22250044] 
{CVE-2015-7613} {CVE-2015-7613}

[2.6.39-400.264.8.el6uek]
- ipc/sem.c: fully initialize sem_array before making it visible 
(Manfred Spraul)  [Orabug: 22250044]  {CVE-2015-7613}
- Initialize msg/shm IPC objects before doing ipc_addid() (Linus 
Torvalds)  [Orabug: 22250044]  {CVE-2015-7613}

[2.6.39-400.264.7.el6uek]
- KVM: svm: unconditionally intercept #DB (Paolo Bonzini)  [Orabug: 
22333698]  {CVE-2015-8104} {CVE-2015-8104}
- KVM: x86: work around infinite loop in microcode when #AC is delivered 
(Eric Northup)  [Orabug: 22333689]  {CVE-2015-5307} {CVE-2015-5307}

[2.6.39-400.264.6.el6uek]
- mlx4_core: Introduce restrictions for PD update (Ajaykumar 
Hotchandani)  - IPoIB: Drop priv->lock before calling ipoib_send() 
(Wengang Wang)  - IPoIB: serialize changing on tx_outstanding (Wengang 
Wang)  [Orabug: 21861366] - IB/mlx4: Implement IB_QP_CREATE_USE_GFP_NOIO 
(Jiri Kosina)  - IB: Add a QP creation flag to use GFP_NOIO allocations 
(Or Gerlitz)  - IB: Return error for unsupported QP creation flags (Or 
Gerlitz)  - IB/ipoib: Calculate csum only when skb->ip_summed is 
CHECKSUM_PARTIAL (Yuval Shaia)  [Orabug: 20873175]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-January/005677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-January/005678.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.39-400.264.13.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.39-400.264.13.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.39-400.264.13.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.39-400.264.13.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.39-400.264.13.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.39-400.264.13.el5uek")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.39-400.264.13.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.39-400.264.13.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.39-400.264.13.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.39-400.264.13.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.39-400.264.13.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.39-400.264.13.el6uek")) flag++;


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
