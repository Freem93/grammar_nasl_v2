#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-813.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75184);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-0231", "CVE-2013-1774", "CVE-2013-1819", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2850", "CVE-2013-2851", "CVE-2013-4162", "CVE-2013-4163");
  script_bugtraq_id(57740, 58202, 58301, 60243, 60341, 60375, 60409, 60874, 60893, 60953, 61411, 61412);
  script_osvdb_id(89903, 90678, 90904, 93755, 94026, 94033, 94035, 94698, 94793, 94853, 95614, 95615);

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2013:1619-1)");
  script_summary(english:"Check for the openSUSE-2013-813 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux kernel was updated to 3.4.63, fixing various bugs and
security issues.

  - Linux 3.4.59 (CVE-2013-2237 bnc#828119).

  - Linux 3.4.57 (CVE-2013-2148 bnc#823517).

  - Linux 3.4.55 (CVE-2013-2232 CVE-2013-2234 CVE-2013-4162
    CVE-2013-4163 bnc#827749 bnc#827750 bnc#831055
    bnc#831058).

  - Drivers: hv: util: Fix a bug in util version negotiation
    code (bnc#838346).

  - vmxnet3: prevent div-by-zero panic when ring resizing
    uninitialized dev (bnc#833321).

  - bnx2x: protect different statistics flows (bnc#814336).

  - bnx2x: Avoid sending multiple statistics queries
    (bnc#814336).

  - Drivers: hv: util: Fix a bug in version negotiation code
    for util services (bnc#828714).

  - Update Xen patches to 3.4.53.

  - netfront: fix kABI after 'reduce gso_max_size to account
    for max TCP header'.

  - netback: don't disconnect frontend when seeing oversize
    packet (bnc#823342).

  - netfront: reduce gso_max_size to account for max TCP
    header.

  - backends: Check for insane amounts of requests on the
    ring.

  - reiserfs: Fixed double unlock in reiserfs_setattr
    failure path.

  - reiserfs: locking, release lock around quota operations
    (bnc#815320).

  - reiserfs: locking, handle nested locks properly
    (bnc#815320).

  - reiserfs: locking, push write lock out of xattr code
    (bnc#815320).

  - ipv6: ip6_append_data_mtu did not care about pmtudisc
    and frag_size (bnc#831055, CVE-2013-4163).

  - af_key: fix info leaks in notify messages (bnc#827749
    CVE-2013-2234).

  - af_key: initialize satype in key_notify_policy_flush()
    (bnc#828119 CVE-2013-2237).

  - ipv6: call udp_push_pending_frames when uncorking a
    socket with (bnc#831058, CVE-2013-4162).

  - ipv6: ip6_sk_dst_check() must not assume ipv6 dst.

  - xfs: fix _xfs_buf_find oops on blocks beyond the
    filesystem end (CVE-2013-1819 bnc#807471).

  - brcmsmac: don't start device when RfKill is engaged
    (bnc#787649).

  - CIFS: Protect i_nlink from being negative (bnc#785542
    bnc#789598).

  - cifs: don't compare uniqueids in cifs_prime_dcache
    unless server inode numbers are in use (bnc#794988).

  - xfs: xfs: fallback to vmalloc for large buffers in
    xfs_compat_attrlist_by_handle (bnc#818053 bnc#807153).

  - xfs: fallback to vmalloc for large buffers in
    xfs_attrlist_by_handle (bnc#818053 bnc#807153).

  - Linux 3.4.53 (CVE-2013-2164 CVE-2013-2851 bnc#822575
    bnc#824295).

  - drivers/cdrom/cdrom.c: use kzalloc() for failing
    hardware (bnc#824295, CVE-2013-2164).

  - fanotify: info leak in copy_event_to_user()
    (CVE-2013-2148 bnc#823517).

  - block: do not pass disk names as format strings
    (bnc#822575 CVE-2013-2851).

  - ext4: avoid hang when mounting non-journal filesystems
    with orphan list (bnc#817377).

  - Linux 3.4.49 (CVE-2013-0231 XSA-43 bnc#801178).

  - Linux 3.4.48 (CVE-2013-1774 CVE-2013-2850 bnc#806976
    bnc#821560).

  - Always include the git commit in KOTD builds This allows
    us not to set it explicitly in builds submitted to the
    official distribution (bnc#821612, bnc#824171).

  - Bluetooth: Really fix registering hci with duplicate
    name (bnc#783858).

  - Bluetooth: Fix registering hci with duplicate name
    (bnc#783858)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=785542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=838346"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-source-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-source-vanilla-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-syms-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-extra-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-extra-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-extra-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-extra-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-base-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-devel-3.4.63-2.44.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.4.63-2.44.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
