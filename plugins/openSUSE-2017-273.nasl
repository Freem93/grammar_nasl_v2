#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-273.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97313);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id("CVE-2017-5006", "CVE-2017-5007", "CVE-2017-5008", "CVE-2017-5009", "CVE-2017-5010", "CVE-2017-5011", "CVE-2017-5012", "CVE-2017-5013", "CVE-2017-5014", "CVE-2017-5015", "CVE-2017-5016", "CVE-2017-5017", "CVE-2017-5018", "CVE-2017-5019", "CVE-2017-5020", "CVE-2017-5021", "CVE-2017-5022", "CVE-2017-5023", "CVE-2017-5024", "CVE-2017-5025", "CVE-2017-5026");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2017-273)");
  script_summary(english:"Check for the openSUSE-2017-273 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google chromium was updated to 56.0.2924.87 :

  - Various small fixes

  - Disabled option to enable/disable plugins in the
    chrome://plugins

  - Changed the build requirement of libavformat to library
    version 57.41.100, as included in ffmpeg 3.1.1, as only
    this version properly supports the public AVStream API
    'codecpar'. 

It also contains the version update to 56.0.2924.76 (bsc#1022049) :

  - CVE-2017-5007: Universal XSS in Blink

  - CVE-2017-5006: Universal XSS in Blink

  - CVE-2017-5008: Universal XSS in Blink

  - CVE-2017-5010: Universal XSS in Blink

  - CVE-2017-5011: Unauthorised file access in Devtools

  - CVE-2017-5009: Out of bounds memory access in WebRTC

  - CVE-2017-5012: Heap overflow in V8

  - CVE-2017-5013: Address spoofing in Omnibox

  - CVE-2017-5014: Heap overflow in Skia

  - CVE-2017-5015: Address spoofing in Omnibox

  - CVE-2017-5019: Use after free in Renderer

  - CVE-2017-5016: UI spoofing in Blink

  - CVE-2017-5017: Uninitialised memory access in webm video

  - CVE-2017-5018: Universal XSS in chrome://apps

  - CVE-2017-5020: Universal XSS in chrome://downloads

  - CVE-2017-5021: Use after free in Extensions

  - CVE-2017-5022: Bypass of Content Security Policy in
    Blink

  - CVE-2017-5023: Type confusion in metrics

  - CVE-2017-5024: Heap overflow in FFmpeg

  - CVE-2017-5025: Heap overflow in FFmpeg

  - CVE-2017-5026: UI spoofing. Credit to Ronni Skansing

  - Enable VAAPI hardware accelerated video decoding.

  - Chromium 55.0.2883.87 :

  - various fixes for crashes and specific wesites

  - update Google pinned certificates"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022049"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:harfbuzz-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:harfbuzz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:harfbuzz-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:harfbuzz-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libharfbuzz-icu0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libharfbuzz-icu0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libharfbuzz-icu0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libharfbuzz-icu0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libharfbuzz0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libharfbuzz0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libharfbuzz0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libharfbuzz0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/22");
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

if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg3-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg3-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ffmpeg3-debugsource-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec57-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavcodec57-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice57-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavdevice57-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter6-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavfilter6-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat57-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavformat57-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample3-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavresample3-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil55-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libavutil55-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc54-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpostproc54-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample2-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswresample2-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale-devel-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale4-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libswscale4-debuginfo-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromedriver-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromedriver-debuginfo-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-debuginfo-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-debugsource-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavcodec57-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavcodec57-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavdevice57-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavdevice57-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavfilter6-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavfilter6-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavformat57-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavformat57-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavresample3-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavresample3-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavutil55-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libavutil55-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpostproc54-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpostproc54-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswresample2-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswresample2-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswscale4-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libswscale4-debuginfo-32bit-3.2.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"harfbuzz-debugsource-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"harfbuzz-devel-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"harfbuzz-tools-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"harfbuzz-tools-debuginfo-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libharfbuzz-icu0-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libharfbuzz-icu0-debuginfo-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libharfbuzz0-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libharfbuzz0-debuginfo-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromedriver-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromedriver-debuginfo-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromium-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromium-debuginfo-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"chromium-debugsource-56.0.2924.87-102.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libharfbuzz-icu0-32bit-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libharfbuzz-icu0-debuginfo-32bit-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libharfbuzz0-32bit-1.4.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libharfbuzz0-debuginfo-32bit-1.4.2-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg3 / ffmpeg3-debuginfo / ffmpeg3-debugsource / etc");
}
