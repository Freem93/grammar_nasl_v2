#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2016-3624.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93905);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:25:11 $");

  script_cve_id("CVE-2016-3134", "CVE-2016-5829");

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2016-3624)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[2.6.39-400.286.2.el6uek]
- HID: hiddev: validate num_values for HIDIOCGUSAGES, HIDIOCSUSAGES 
commands (Scott Bauer)  [Orabug: 24798694]  {CVE-2016-5829}

[2.6.39-400.286.1.el6uek]
- Revert 'rds: skip rx/tx work when destroying connection' (Brian Maly) 
  [Orabug: 24790158]

[2.6.39-400.285.1.el6uek]
- netfilter: x_tables: speed up jump target validation (Florian 
Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: enforce nul-terminated table name from getsockopt 
GET_ENTRIES (Pablo Neira Ayuso)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: remove unused comefrom hookmask argument (Florian Westphal) 
  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: introduce and use xt_copy_counters_from_user 
(Florian Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: do compat validation via translate_table (Florian 
Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: xt_compat_match_from_user doesn't need a retval 
(Florian Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: ip6_tables: simplify translate_compat_table args (Florian 
Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: ip_tables: simplify translate_compat_table args (Florian 
Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: arp_tables: simplify translate_compat_table args (Florian 
Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: don't reject valid target size on some 
architectures (Florian Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: validate all offsets and sizes in a rule (Florian 
Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: check for bogus target offset (Florian Westphal) 
  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: check standard target size too (Florian Westphal) 
  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: add compat version of xt_check_entry_offsets 
(Florian Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: assert minimum target size (Florian Westphal) 
[Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: kill check_entry helper (Florian Westphal) 
[Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: add and use xt_check_entry_offsets (Florian 
Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: validate targets of jumps (Florian Westphal) 
[Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: fix unconditional helper (Florian Westphal) 
[Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: validate targets of jumps (Florian Westphal) 
[Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: don't move to non-existent next rule (Florian 
Westphal)  [Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: fix unconditional helper (Florian Westphal) 
[Orabug: 24690302]  {CVE-2016-3134}
- netfilter: x_tables: check for size overflow (Florian Westphal) 
[Orabug: 24690302]  {CVE-2016-3134}
- ocfs2: Fix double put of recount tree in ocfs2_lock_refcount_tree() 
(Ashish Samant)  [Orabug: 24587406]
- TTY: do not reset master's packet mode (Jiri Slaby)  [Orabug: 24569399]
- ocfs2: Fix start offset to ocfs2_zero_range_for_truncate() (Ashish 
Samant)  [Orabug: 24500401]
- rds: skip rx/tx work when destroying connection (Wengang Wang) 
[Orabug: 24314773]
- Revert 'IPoIB: serialize changing on tx_outstanding' (Wengang Wang) 
[Orabug: 23745787]
- xen/events: document behaviour when scanning the start word for events 
(Dongli Zhang)  [Orabug: 23083945]
- xen/events: mask events when changing their VCPU binding (Dongli 
Zhang)  [Orabug: 23083945]
- xen/events: initialize local per-cpu mask for all possible events 
(Dongli Zhang)  [Orabug: 23083945]
- IB/mlx4: Replace kfree with kvfree in mlx4_ib_destroy_srq (Wengang 
Wang)  [Orabug: 22570922]
- NFS: Remove BUG_ON() calls from the generic writeback code (Trond 
Myklebust)  [Orabug: 22386565]
- ocfs2: return non-zero st_blocks for inline data (John Haxby) 
[Orabug: 22218262]
- oracleasm: Classify device connectivity issues as global errors 
(Martin K. Petersen)  [Orabug: 21760143]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-October/006399.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-October/006400.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");
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
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.39-400.286.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.39-400.286.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.39-400.286.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.39-400.286.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.39-400.286.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.39-400.286.2.el5uek")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.39-400.286.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.39-400.286.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.39-400.286.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.39-400.286.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.39-400.286.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.39-400.286.2.el6uek")) flag++;


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
