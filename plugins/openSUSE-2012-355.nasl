#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-355.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74660);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2012-2807", "CVE-2012-2815", "CVE-2012-2816", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2819", "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2823", "CVE-2012-2825", "CVE-2012-2826", "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831", "CVE-2012-2834");
  script_osvdb_id(83238, 83241, 83242, 83243, 83244, 83245, 83247, 83250, 83252, 83253, 83254, 83255, 83256, 83257, 83266);

  script_name(english:"openSUSE Security Update : chromium / v8 (openSUSE-SU-2012:0813-1)");
  script_summary(english:"Check for the openSUSE-2012-355 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update Chromium to 22.0.1190

  - Security Fixes (bnc#769181) :

  - CVE-2012-2815: Leak of iframe fragment id

  - CVE-2012-2816: Prevent sandboxed processes interfering
    with each other

  - CVE-2012-2817: Use-after-free in table section handling

  - CVE-2012-2818: Use-after-free in counter layout

  - CVE-2012-2819: Crash in texture handling

  - CVE-2012-2820: Out-of-bounds read in SVG filter handling

  - CVE-2012-2821: Autofill display problem

  - CVE-2012-2823: Use-after-free in SVG resource handling

  - CVE-2012-2826: Out-of-bounds read in texture conversion

  - CVE-2012-2829: Use-after-free in first-letter handling

  - CVE-2012-2830: Wild pointer in array value setting

  - CVE-2012-2831: Use-after-free in SVG reference handling

  - CVE-2012-2834: Integer overflow in Matroska container

  - CVE-2012-2825: Wild read in XSL handling

  - CVE-2012-2807: Integer overflows in libxml

  - Fix update-alternatives within the spec-file

  - Update v8 to 3.12.5.0

  - Fixed Chromium issues: 115100, 129628, 131994, 132727,
    132741, 132742, 133211

  - Fixed V8 issues: 915, 1914, 2034, 2087, 2094, 2134,
    2156, 2166, 2172, 2177, 2179, 2185

  - Added --extra-code flag to mksnapshot to load JS code
    into the VM before creating the snapshot.

  - Support 'restart call frame' command in the debugger.

  - Fixed lazy sweeping heuristics to prevent old-space
    expansion. (issue 2194)

  - Fixed sharing of literal boilerplates for optimized
    code. (issue 2193)

  - Removed -fomit-frame-pointer flag from Release builds to
    make the stack walkable by TCMalloc (Chromium issue
    133723).

  - Expose more detailed memory statistics (issue 2201).

  - Fixed Harmony Maps and WeakMaps for undefined values
    (Chromium issue 132744).

  - Update v8 to 3.11.10.6

  - Implemented heap profiler memory usage reporting.

  - Preserved error message during finally block in
    try..finally. (Chromium issue 129171)

  - Fixed EnsureCanContainElements to properly handle double
    values. (issue 2170)

  - Improved heuristics to keep objects in fast mode with
    inherited constructors.

  - Performance and stability improvements on all platforms.

  - Implemented ES5-conformant semantics for inherited
    setters and read-only properties. Currently behind
    --es5_readonly flag, because it breaks WebKit bindings.

  - Exposed last seen heap object id via v8 public api.

  - Update v8 to 3.11.8.0

  - Avoid overdeep recursion in regexp where a guarded
    expression with a minimum repetition count is inside
    another quantifier. (Chromium issue 129926)

  - Fixed missing write barrier in store field stub. (issues
    2143, 1465, Chromium issue 129355)

  - Proxies: Fixed receiver for setters inherited from
    proxies.

  - Proxies: Fixed ToStringArray function so that it does
    not reject some keys. (issue 1543)

  - Update v8 to 3.11.7.0

  - Get better function names in stack traces.

  - Fixed RegExp.prototype.toString for incompatible
    receivers (issue 1981).

  - Some cleanup to common.gypi. This fixes some host/target
    combinations that weren't working in the Make build on
    Mac.

  - Handle EINTR in socket functions and continue incomplete
    sends. (issue 2098)

  - Fixed python deprecations. (issue 1391)

  - Made socket send and receive more robust and return 0 on
    failure. (Chromium issue 15719)

  - Fixed GCC 4.7 (C++11) compilation. (issue 2136)

  - Set '-m32' option for host and target platforms

  - Performance and stability improvements on all platforms."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769181"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium / v8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-debuginfo-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-22.0.1190.0-1.26.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-3.12.5.0-1.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-debuginfo-3.12.5.0-1.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-debugsource-3.12.5.0-1.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-devel-3.12.5.0-1.30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-private-headers-devel-3.12.5.0-1.30.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
