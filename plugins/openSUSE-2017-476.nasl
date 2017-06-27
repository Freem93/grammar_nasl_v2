#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-476.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99427);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/20 13:20:51 $");

  script_cve_id("CVE-2017-6827", "CVE-2017-6828", "CVE-2017-6829", "CVE-2017-6830", "CVE-2017-6831", "CVE-2017-6832", "CVE-2017-6833", "CVE-2017-6834", "CVE-2017-6835", "CVE-2017-6836", "CVE-2017-6837", "CVE-2017-6838", "CVE-2017-6839");

  script_name(english:"openSUSE Security Update : audiofile (openSUSE-2017-476)");
  script_summary(english:"Check for the openSUSE-2017-476 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This audiofile update fixes the following issue :

Security issues fixed :

  - CVE-2017-6827: heap-based buffer overflow in
    MSADPCM::initializeCoefficients (MSADPCM.cpp)
    (bsc#1026979)

  - CVE-2017-6828: heap-based buffer overflow in readValue
    (FileHandle.cpp) (bsc#1026980)

  - CVE-2017-6829: global buffer overflow in decodeSample
    (IMA.cpp) (bsc#1026981)

  - CVE-2017-6830: heap-based buffer overflow in
    alaw2linear_buf (G711.cpp) (bsc#1026982)

  - CVE-2017-6831: heap-based buffer overflow in
    IMA::decodeBlockWAVE (IMA.cpp) (bsc#1026983)

  - CVE-2017-6832: heap-based buffer overflow in
    MSADPCM::decodeBlock (MSADPCM.cpp) (bsc#1026984)

  - CVE-2017-6833: divide-by-zero in BlockCodec::runPull
    (BlockCodec.cpp) (bsc#1026985)

  - CVE-2017-6834: heap-based buffer overflow in
    ulaw2linear_buf (G711.cpp) (bsc#1026986)

  - CVE-2017-6835: divide-by-zero in BlockCodec::reset1
    (BlockCodec.cpp) (bsc#1026988)

  - CVE-2017-6836: heap-based buffer overflow in
    Expand3To4Module::run (SimpleModule.h) (bsc#1026987)

  - CVE-2017-6837, CVE-2017-6838, CVE-2017-6839: multiple
    ubsan crashes (bsc#1026978)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026988"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected audiofile packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaudiofile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaudiofile1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaudiofile1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaudiofile1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/18");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"audiofile-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"audiofile-debuginfo-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"audiofile-debugsource-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"audiofile-devel-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libaudiofile1-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libaudiofile1-debuginfo-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"audiofile-devel-32bit-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libaudiofile1-32bit-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libaudiofile1-debuginfo-32bit-0.3.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"audiofile-0.3.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"audiofile-debuginfo-0.3.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"audiofile-debugsource-0.3.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"audiofile-devel-0.3.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libaudiofile1-0.3.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libaudiofile1-debuginfo-0.3.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"audiofile-devel-32bit-0.3.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libaudiofile1-32bit-0.3.6-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libaudiofile1-debuginfo-32bit-0.3.6-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "audiofile / audiofile-debuginfo / audiofile-debugsource / etc");
}
