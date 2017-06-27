#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-472.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90562);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/04/18 15:25:37 $");

  script_cve_id("CVE-2015-5276");

  script_name(english:"openSUSE Security Update : gcc5 (openSUSE-2016-472)");
  script_summary(english:"Check for the openSUSE-2016-472 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The GNU Compiler Collection was updated to version 5.3.1, which brings
several fixes and enhancements.

The following security issue has been fixed :

  - Fix C++11 std::random_device short read issue that could
    lead to predictable randomness. (CVE-2015-5276,
    bsc#945842)

The following non-security issues have been fixed :

  - Enable frame pointer for TARGET_64BIT_MS_ABI when stack
    is misaligned. Fixes internal compiler error when
    building Wine. (bsc#966220)

  - Fix a PowerPC specific issue in gcc-go that broke
    compilation of newer versions of Docker. (bsc#964468)

  - Fix HTM built-ins on PowerPC. (bsc#955382)

  - Fix libgo certificate lookup. (bsc#953831)

  - Suppress deprecated-declarations warnings for inline
    definitions of deprecated virtual methods. (bsc#939460)

  - Build s390[x] with '--with-tune=z9-109 --with-arch=z900'
    on SLE11 again. (bsc#954002)

  - Revert accidental libffi ABI breakage on aarch64.
    (bsc#968771)

  - On x86_64, set default 32bit code generation to
    -march=x86-64 rather than -march=i586.

  - Add experimental File System TS library. This update was
    imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968771"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gcc5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpp5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-ada");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-ada-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-ada-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-c++-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-fortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-fortran-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-fortran-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-go-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-go-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gcc5-testresults");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libada5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasan2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libatomic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcilkrts5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcilkrts5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcilkrts5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi-devel-gcc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi-devel-gcc5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi-gcc5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libffi4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgcc_s1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfortran3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo7-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgo7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgomp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libitm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpx0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpx0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpx0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpxwrappers0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpxwrappers0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpxwrappers0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpxwrappers0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libquadmath0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-devel-gcc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-devel-gcc5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libubsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/18");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"cpp5-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cpp5-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-ada-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-ada-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-c++-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-c++-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-debugsource-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-fortran-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-fortran-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-go-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-go-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-info-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-locale-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gcc5-testresults-5.3.1+r233831-6.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libada5-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libada5-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libasan2-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libasan2-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libatomic1-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libatomic1-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcilkrts5-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcilkrts5-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libffi-devel-gcc5-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libffi-gcc5-debugsource-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libffi4-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libffi4-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgcc_s1-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgcc_s1-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgfortran3-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgfortran3-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgo7-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgo7-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgomp1-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgomp1-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libitm1-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libitm1-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmpx0-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmpx0-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmpxwrappers0-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmpxwrappers0-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libquadmath0-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libquadmath0-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstdc++6-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstdc++6-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstdc++6-devel-gcc5-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libstdc++6-locale-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libubsan0-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libubsan0-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gcc5-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gcc5-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gcc5-ada-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gcc5-c++-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gcc5-fortran-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gcc5-go-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libada5-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libada5-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libasan2-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libasan2-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libatomic1-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libatomic1-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcilkrts5-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libffi-devel-gcc5-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libffi4-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libffi4-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgcc_s1-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgcc_s1-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgfortran3-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgfortran3-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgo7-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgo7-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgomp1-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgomp1-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libitm1-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libitm1-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"liblsan0-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"liblsan0-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmpx0-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmpx0-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmpxwrappers0-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmpxwrappers0-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libquadmath0-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libstdc++6-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libstdc++6-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libstdc++6-devel-gcc5-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtsan0-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtsan0-debuginfo-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libubsan0-32bit-5.3.1+r233831-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-5.3.1+r233831-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc5-testresults / cpp5 / cpp5-debuginfo / gcc5 / gcc5-ada / etc");
}
