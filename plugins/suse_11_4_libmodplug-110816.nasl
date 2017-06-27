#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libmodplug-5004.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75902);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-1761", "CVE-2011-2911", "CVE-2011-2912", "CVE-2011-2913", "CVE-2011-2914", "CVE-2011-2915");

  script_name(english:"openSUSE Security Update : libmodplug (openSUSE-SU-2011:0943-1)");
  script_summary(english:"Check for the libmodplug-5004 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libmodplug0 fixes the following issues :

1) An integer overflow error exists within the 'CSoundFile::ReadWav()'
function (src/load_wav.cpp) when processing certain WAV files. This
can be exploited to cause a heap-based buffer overflow by tricking a
user into opening a specially crafted WAV file. (CVE-2011-2911)

2) Boundary errors within the 'CSoundFile::ReadS3M()' function
(src/load_s3m.cpp) when processing S3M files can be exploited to cause
stack-based buffer overflows by tricking a user into opening a
specially crafted S3M file. (CVE-2011-2912)

3) An off-by-one error within the 'CSoundFile::ReadAMS()' function
(src/load_ams.cpp) can be exploited to cause a stack corruption by
tricking a user into opening a specially crafted AMS file.
(CVE-2011-2913)

4) An off-by-one error within the 'CSoundFile::ReadDSM()' function
(src/load_dms.cpp) can be exploited to cause a memory corruption by
tricking a user into opening a specially crafted DSM file.
(CVE-2011-2914)

5) An off-by-one error within the 'CSoundFile::ReadAMS2()' function
(src/load_ams.cpp) can be exploited to cause a memory corruption by
tricking a user into opening a specially crafted AMS file.
(CVE-2011-2915)

Also an overflow in the ABC loader was fixed. (CVE-2011-1761)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-08/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=710726"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmodplug packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/16");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libmodplug-debugsource-0.8.8.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmodplug-devel-0.8.8.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmodplug0-0.8.8.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmodplug0-debuginfo-0.8.8.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmodplug0-32bit-0.8.8.4-2.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmodplug0-debuginfo-32bit-0.8.8.4-2.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmodplug");
}
