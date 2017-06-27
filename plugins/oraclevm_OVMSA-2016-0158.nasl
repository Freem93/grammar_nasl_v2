#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0158.
#

include("compat.inc");

if (description)
{
  script_id(94929);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2015-8374", "CVE-2016-2117", "CVE-2016-3134", "CVE-2016-4470", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5195", "CVE-2016-5829");
  script_osvdb_id(130832, 135678, 135961, 140046, 140493, 140494, 140558, 146061);
  script_xref(name:"IAVA", value:"2016-A-0306");

  script_name(english:"OracleVM 3.2 : Unbreakable / etc (OVMSA-2016-0158) (Dirty COW)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - mm, gup: close FOLL MAP_PRIVATE race (Linus Torvalds)
    [Orabug: 24928646] (CVE-2016-5195)

  - HID: hiddev: validate num_values for HIDIOCGUSAGES,
    HIDIOCSUSAGES commands (Scott Bauer) [Orabug: 24798694]
    (CVE-2016-5829)

  - Revert 'rds: skip rx/tx work when destroying connection'
    (Brian Maly) [Orabug: 24790158]

  - netfilter: x_tables: speed up jump target validation
    (Florian Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: enforce nul-terminated table name
    from getsockopt GET_ENTRIES (Pablo Neira Ayuso) [Orabug:
    24690302] (CVE-2016-3134)

  - netfilter: remove unused comefrom hookmask argument
    (Florian Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: introduce and use
    xt_copy_counters_from_user (Florian Westphal) [Orabug:
    24690302] (CVE-2016-3134)

  - netfilter: x_tables: do compat validation via
    translate_table (Florian Westphal) [Orabug: 24690302]
    (CVE-2016-3134)

  - netfilter: x_tables: xt_compat_match_from_user doesn't
    need a retval (Florian Westphal) [Orabug: 24690302]
    (CVE-2016-3134)

  - netfilter: ip6_tables: simplify translate_compat_table
    args (Florian Westphal) [Orabug: 24690302]
    (CVE-2016-3134)

  - netfilter: ip_tables: simplify translate_compat_table
    args (Florian Westphal) [Orabug: 24690302]
    (CVE-2016-3134)

  - netfilter: arp_tables: simplify translate_compat_table
    args (Florian Westphal) [Orabug: 24690302]
    (CVE-2016-3134)

  - netfilter: x_tables: don't reject valid target size on
    some architectures (Florian Westphal) [Orabug: 24690302]
    (CVE-2016-3134)

  - netfilter: x_tables: validate all offsets and sizes in a
    rule (Florian Westphal) [Orabug: 24690302]
    (CVE-2016-3134)

  - netfilter: x_tables: check for bogus target offset
    (Florian Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: check standard target size too
    (Florian Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: add compat version of
    xt_check_entry_offsets (Florian Westphal) [Orabug:
    24690302] (CVE-2016-3134)

  - netfilter: x_tables: assert minimum target size (Florian
    Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: kill check_entry helper (Florian
    Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: add and use xt_check_entry_offsets
    (Florian Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: validate targets of jumps (Florian
    Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: fix unconditional helper (Florian
    Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: validate targets of jumps (Florian
    Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: don't move to non-existent next
    rule (Florian Westphal) [Orabug: 24690302]
    (CVE-2016-3134)

  - netfilter: x_tables: fix unconditional helper (Florian
    Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - netfilter: x_tables: check for size overflow (Florian
    Westphal) [Orabug: 24690302] (CVE-2016-3134)

  - ocfs2: Fix double put of recount tree in
    ocfs2_lock_refcount_tree (Ashish Samant) [Orabug:
    24587406]

  - TTY: do not reset master's packet mode (Jiri Slaby)
    [Orabug: 24569399]

  - ocfs2: Fix start offset to ocfs2_zero_range_for_truncate
    (Ashish Samant) [Orabug: 24500401]

  - rds: skip rx/tx work when destroying connection (Wengang
    Wang) 

  - Revert 'IPoIB: serialize changing on tx_outstanding'
    (Wengang Wang) 

  - xen/events: document behaviour when scanning the start
    word for events (Dongli Zhang) [Orabug: 23083945]

  - xen/events: mask events when changing their VCPU binding
    (Dongli Zhang) [Orabug: 23083945]

  - xen/events: initialize local per-cpu mask for all
    possible events (Dongli Zhang) [Orabug: 23083945]

  - IB/mlx4: Replace kfree with kvfree in
    mlx4_ib_destroy_srq (Wengang Wang) [Orabug: 22570922]

  - NFS: Remove BUG_ON calls from the generic writeback code
    (Trond Myklebust) [Orabug: 22386565]

  - ocfs2: return non-zero st_blocks for inline data (John
    Haxby) 

  - oracleasm: Classify device connectivity issues as global
    errors (Martin K. Petersen) [Orabug: 21760143]

  - Btrfs: fix truncation of compressed and inlined extents
    (Divya Indi) [Orabug: 22307286] (CVE-2015-8374)

  - Btrfs: fix file corruption and data loss after cloning
    inline extents (Divya Indi) [Orabug: 22307286]
    (CVE-2015-8374)

  - netfilter: x_tables: make sure e->next_offset covers
    remaining blob size (Florian Westphal) [Orabug:
    24682073] (CVE-2016-4997) (CVE-2016-4998)

  - netfilter: x_tables: validate e->target_offset early
    (Florian Westphal) [Orabug: 24682071] (CVE-2016-4997)
    (CVE-2016-4998)

  - rds: schedule local connection activity in proper
    workqueue (Ajaykumar Hotchandani) [Orabug: 22819661]

  - ib_core: make wait_event uninterruptible in
    ib_flush_fmr_pool (Avinash Repaka) [Orabug: 24525022]

  - net/mlx4: Support shutdown interface (Ajaykumar
    Hotchandani) 

  - KEYS: potential uninitialized variable (Dan Carpenter)
    [Orabug: 24393863] (CVE-2016-4470)

  - atl2: Disable unimplemented scatter/gather feature (Ben
    Hutchings) [Orabug: 23703990] (CVE-2016-2117)

  - mlx4_core: add module parameter to disable background
    init (Mukesh Kacker) [Orabug: 23292107]

  - NFSv4: Don't decode fs_locations if we didn't ask for
    them... (Trond Myklebust) [Orabug: 23633714]

  - mm/slab: Improve performance of slabinfo stats gathering
    (Aruna Ramakrishna) [Orabug: 23050884]

  - offload ib subnet manager port and node get info query
    handling. (Rama Nichanamatlu) [Orabug: 22521735]

  - fix typo/thinko in get_random_bytes (Tony Luck) [Orabug:
    23726807]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-November/000582.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77f7352c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-2.6.39-400.286.3.el5uek")) flag++;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-firmware-2.6.39-400.286.3.el5uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
