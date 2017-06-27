#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1500.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95976);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-5009");

  script_name(english:"openSUSE Security Update : ceph (openSUSE-2016-1500)");
  script_summary(english:"Check for the openSUSE-2016-1500 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ceph was updated to version 10.2.4 and fixes the following issues :

  - A moncommand with empty prefix could crash the monitor
    (boo#987144, CVE-2016-5009)

  - Detect crc32 extension support from assembler on AArch64
    (boo#999688)

  - Failing file operations on kernel based cephfs mount
    point could leave unaccessible file behind on hammer
    0.94.7 (boo#985232)

  - Fixed boo#1008501

  + ceph_volume_client: fix _recover_auth_meta() method

  + ceph_volume_client: check if volume metadata is empty

  + ceph_volume_client: fix partial auth recovery

  - Avoid ~100% CPU load after OSD creation / first OSD
    start (boo#1014338)

  - Fixed boo#990438: civetweb HTTPS support not working

  - Avoid systemd limiting OSDs (boo#1007216)

  - Fix 'make check' when building unit tests with
    --with-xio (boo#977940)

  - Fix build for ppc64le (boo#982141)

  - Including performance fix for linux dcache hash
    algorithm (boo#1005179)

  - Fix invalid command in SOC7 (boo#1008894)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999688"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.2", reference:"ceph-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-base-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-base-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-common-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-common-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-fuse-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-fuse-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-mds-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-mds-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-mon-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-mon-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-osd-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-osd-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-radosgw-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-radosgw-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-resource-agents-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-test-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ceph-test-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcephfs-devel-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcephfs1-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcephfs1-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librados-devel-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librados-devel-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librados2-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librados2-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libradosstriper-devel-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libradosstriper1-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libradosstriper1-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librbd-devel-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librbd1-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librbd1-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librgw-devel-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librgw2-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"librgw2-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-ceph-compat-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-cephfs-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-cephfs-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-rados-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-rados-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-rbd-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-rbd-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-fuse-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-fuse-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-mirror-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-mirror-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-nbd-10.2.4+git.1481215985.12b091b-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"rbd-nbd-debuginfo-10.2.4+git.1481215985.12b091b-4.1") ) flag++;

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
