#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-197.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97000);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/06 15:09:25 $");

  script_cve_id("CVE-2016-10132", "CVE-2016-10133", "CVE-2016-10141");

  script_name(english:"openSUSE Security Update : mupdf (openSUSE-2017-197)");
  script_summary(english:"Check for the openSUSE-2017-197 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mupdf to version 1.10a fixes the following issues :

These security issues were fixed :

  - CVE-2016-10132: NULL pointer dereference in regexp
    because of a missing check after allocating memory
    allowing for DoS (bsc#1019877).

  - CVE-2016-10133: Heap buffer overflow write in
    js_stackoverflow allowing for DoS or possible code
    execution (bsc#1019877).

  - CVE-2016-10141: An integer overflow vulnerability
    triggered by a regular expression with nested
    repetition. A successful exploitation of this issue can
    lead to code execution or a denial of service (buffer
    overflow) condition (bsc#1019877).

These non-security issues were fixed :

  - A bug with mutool and saving PDF files using the 'ascii'
    option has been fixed.

  - Stop defining OPJ_STATIC

  - FictionBook (FB2) e-book support.

  - Simple SVG parser (a small subset of SVG only).

  - mutool convert: a new document conversion tool and
    interface.

  - Multi-threaded rendering in mudraw.

  - Updated base 14 fonts from URW.

  - New CJK font with language specific variants.

  - Hyperlink support in EPUB.

  - Alpha channel is now optional in pixmaps.

  - More aggressive purging of cached objects.

  - Partial image decoding for lower memory use when
    banding.

  - Reduced default set of built-in CMap tables to the
    minimum required.

  - FZ_ENABLE_PDF, _XPS, _JS, to disable features at compile
    time.

  - Function level linking.

  - Dropped pdf object generation numbers from public
    interfaces.

  - Simplified PDF page, xobject, and annotation internals.

  - Closing and freeing devices and writers are now separate
    steps.

  - Improved PDF annotation editing interface (still a work
    in progress).

  - Document writer interface.

  - Banded image writer interface.

  - Bidirectional layout for Arabic and Hebrew scripts.

  - Shaping complex scripts for EPUB text layout.

  - Noto fallback fonts for EPUB layout.

  - mutool create :

  - Create new PDF files from scratch.

  - Read an annotated content stream in a text file and
    write a PDF file, automatically embedding font and image
    resources.

  - mutool run :

  + Run JavaScript scripts with MuPDF bindings.

  + The interface is similar to the new Java interface.

  - mutool draw :

  + Optional multi-threaded operation (Windows and
    pthreads).

  + Optional low memory mode (primarily for testing).

  - Set to best anti-alias mode (8) by default. 

  - Ship mupdf-x11-curl as default mupdf. Drop non-curl
    version.

  - New URW fonts with greek and cyrillic.

  - 64-bit file support.

  - Updated FreeType to version 2.6.1.

  - Various font substitution bug fixes.

  - EPUB improvements: User style sheets, GIF images, Table
    of Contents, CJK text, Page margins and many bug fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019877"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mupdf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mupdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mupdf-devel-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/06");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"mupdf-1.10a-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mupdf-devel-static-1.10a-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mupdf / mupdf-devel-static");
}
