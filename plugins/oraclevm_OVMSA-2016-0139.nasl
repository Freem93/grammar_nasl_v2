#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0139.
#

include("compat.inc");

if (description)
{
  script_id(93908);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2016-3134", "CVE-2016-5829");
  script_osvdb_id(135678, 140558);

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2016-0139)");
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

  - HID: hiddev: validate num_values for HIDIOCGUSAGES,
    HIDIOCSUSAGES commands (Scott Bauer) [Orabug: 24798695]
    (CVE-2016-5829)

  - Revert 'rds: skip rx/tx work when destroying connection'
    (Brian Maly) [Orabug: 24790116]

  - scsi_sysfs: protect against double execution of
    __scsi_remove_device (Vitaly Kuznetsov) [Orabug:
    23720563]

  - ocfs2: Fix double put of recount tree in
    ocfs2_lock_refcount_tree (Ashish Samant) [Orabug:
    24691666]

  - netfilter: x_tables: speed up jump target validation
    (Florian Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: enforce nul-terminated table name
    from getsockopt GET_ENTRIES (Pablo Neira Ayuso) [Orabug:
    24690304] (CVE-2016-3134)

  - netfilter: remove unused comefrom hookmask argument
    (Florian Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: introduce and use
    xt_copy_counters_from_user (Florian Westphal) [Orabug:
    24690304] (CVE-2016-3134)

  - netfilter: x_tables: do compat validation via
    translate_table (Florian Westphal) [Orabug: 24690304]
    (CVE-2016-3134)

  - netfilter: x_tables: xt_compat_match_from_user doesn't
    need a retval (Florian Westphal) [Orabug: 24690304]
    (CVE-2016-3134)

  - netfilter: ip6_tables: simplify translate_compat_table
    args (Florian Westphal) [Orabug: 24690304]
    (CVE-2016-3134)

  - netfilter: ip_tables: simplify translate_compat_table
    args (Florian Westphal) [Orabug: 24690304]
    (CVE-2016-3134)

  - netfilter: arp_tables: simplify translate_compat_table
    args (Florian Westphal) [Orabug: 24690304]
    (CVE-2016-3134)

  - netfilter: x_tables: don't reject valid target size on
    some architectures (Florian Westphal) [Orabug: 24690304]
    (CVE-2016-3134)

  - netfilter: x_tables: validate all offsets and sizes in a
    rule (Florian Westphal) [Orabug: 24690304]
    (CVE-2016-3134)

  - netfilter: x_tables: check for bogus target offset
    (Florian Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: check standard target size too
    (Florian Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: add compat version of
    xt_check_entry_offsets (Florian Westphal) [Orabug:
    24690304] (CVE-2016-3134)

  - netfilter: x_tables: assert minimum target size (Florian
    Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: kill check_entry helper (Florian
    Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: add and use xt_check_entry_offsets
    (Florian Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: validate targets of jumps (Florian
    Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: fix unconditional helper (Florian
    Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: validate targets of jumps (Florian
    Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: don't move to non-existent next
    rule (Florian Westphal) [Orabug: 24690304]
    (CVE-2016-3134)

  - netfilter: x_tables: fix unconditional helper (Florian
    Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - netfilter: x_tables: check for size overflow (Florian
    Westphal) [Orabug: 24690304] (CVE-2016-3134)

  - NFSv4: Fail I/O if the state recovery fails irrevocably
    (Trond Myklebust) [Orabug: 24681407]

  - rds: skip rx/tx work when destroying connection (Wengang
    Wang) 

  - ocfs2: Fix start offset to ocfs2_zero_range_for_truncate
    (Ashish Samant) [Orabug: 23747627]

  - sched/core: Clear the root_domain cpumasks in
    init_rootdomain (Xunlei Pang) [Orabug: 23518545]

  - ocfs2: move dquot_initialize in ocfs2_delete_inode
    somewhat later (Jan Kara) [Orabug: 23097098]

  - fuse: fix typo while displaying fuse numa mount option
    (Ashish Samant)

  - IB/mlx4: Replace kfree with kvfree in
    mlx4_ib_destroy_srq (Wengang Wang) [Orabug: 22570521]

  - ocfs2: return non-zero st_blocks for inline data (John
    Haxby) 

  - watchdog: update watchdog_thresh properly (Michal Hocko)
    [Orabug: 21868337]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-October/000557.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de07eae7"
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.13.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.13.2.el6uek")) flag++;

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
