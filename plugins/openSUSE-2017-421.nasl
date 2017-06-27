#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-421.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99179);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/04 13:36:41 $");

  script_cve_id("CVE-2016-9579");

  script_name(english:"openSUSE Security Update : ceph (openSUSE-2017-421)");
  script_summary(english:"Check for the openSUSE-2017-421 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This ceph version update to 10.2.6+git fixes the following issues :

Security issues fixed :

  - CVE-2016-9579: RGW server DoS via request with invalid
    HTTP Origin header (boo#1014986).

Bugfixes :

  - Update to version 10.2.6+git.1489493035.3ad7a68

  - 'tools/rados: default to include clone objects when
    excuting 'cache-flush-evict-all' (boo#1003891)

  - mon,ceph-disk: add lockbox permissions to bootstrap-osd
    (boo#1008435)

  - 'ceph_volume_client: fix _recover_auth_meta() method'
    (boo#1008501)

  - 'systemd/ceph-disk: reduce ceph-disk flock contention'
    (boo#1012100)

  - 'doc: add verbiage to rbdmap manpage' and 'Add Install
    section to systemd rbdmap.service file' (boo#1015748)

  - ceph-disk: systemd unit must run after local-fs.target
    (boo#1012100)

  - build/ops: restart ceph-osd@.service after 20s instead
    of 100ms (boo#1019616)

  - doc: add verbiage to rbdmap manpage and mention rbdmap
    in RBD quick start (boo#1015748)

  - doc: ceph-deploy man: remove references to mds destroy.
    Not implemented (boo#970642)

Feature enhancements :

  - FATE#321098 :

  - rpm: deobfuscate SUSE-specific bconds

  - rpm: consider xio bcond on x86_64 and aarch64 only

  - rpm: remove s390 from SES ExclusiveArch

  - rpm: limit lttng/babeltrace to architectures

  - rpm: limit xio build

  - rpm: enable build for s390(x) in SLE

  - rpm: add 'without valgrind_devel' configure option"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/321098"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ceph packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ceph-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-mirror-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-nbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"ceph-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-base-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-base-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-common-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-common-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-fuse-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-fuse-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-mds-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-mds-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-mon-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-mon-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-osd-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-osd-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-radosgw-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-radosgw-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-resource-agents-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-test-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-test-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcephfs-devel-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcephfs1-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcephfs1-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librados-devel-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librados-devel-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librados2-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librados2-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libradosstriper-devel-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libradosstriper1-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libradosstriper1-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librbd-devel-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librbd1-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librbd1-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librgw-devel-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librgw2-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librgw2-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-ceph-compat-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-cephfs-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-cephfs-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-rados-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-rados-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-rbd-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-rbd-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-fuse-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-fuse-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-mirror-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-mirror-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-nbd-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-nbd-debuginfo-10.2.6+git.1489493035.3ad7a68-6.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-test / ceph-test-debuginfo / ceph / ceph-base / etc");
}
