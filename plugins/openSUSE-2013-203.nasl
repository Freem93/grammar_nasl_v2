#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-203.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74920);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2013-0879", "CVE-2013-0880", "CVE-2013-0881", "CVE-2013-0882", "CVE-2013-0883", "CVE-2013-0884", "CVE-2013-0885", "CVE-2013-0886", "CVE-2013-0887", "CVE-2013-0888", "CVE-2013-0889", "CVE-2013-0890", "CVE-2013-0891", "CVE-2013-0892", "CVE-2013-0893", "CVE-2013-0894", "CVE-2013-0895", "CVE-2013-0896", "CVE-2013-0897", "CVE-2013-0898", "CVE-2013-0899", "CVE-2013-0900");
  script_osvdb_id(90521, 90522, 90523, 90524, 90525, 90526, 90527, 90528, 90529, 90530, 90531, 90532, 90533, 90534, 90535, 90536, 90537, 90538, 90539, 90540, 90541, 90542, 90950, 101163, 101164, 101165, 101166, 101167, 101168);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2013:0454-1)");
  script_summary(english:"Check for the openSUSE-2013-203 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"chromium was updated to version 27.0.1425 having both stability and
security fixes :

  - Bug and stability fixes :

  - Fixed crash after clicking through malware warning.
    (Issue: 173986)

  - Fixed broken command line to create extensions with
    locale info (Issue: 176187)

  - Hosted apps in Chrome will always be opened from app
    launcher. (Issue: 176267)

  - Added modal confirmation dialog to the enterprise
    profile sign-in flow. (Issue: 171236)

  - Fixed a crash with autofill. (Issues: 175454, 176576)

  - Fixed issues with sign-in. (Issues: 175672, 175819,
    175541, 176190)

  - Fixed spurious profile shortcuts created with a
    system-level install. (Issue: 177047)

  - Fixed the background tab flashing with certain themes.
    (Issue: 175426)

  - Security Fixes: (bnc#804986)

  - High CVE-2013-0879: Memory corruption with web audio
    node

  - High CVE-2013-0880: Use-after-free in database handling

  - Medium CVE-2013-0881: Bad read in Matroska handling

  - High CVE-2013-0882: Bad memory access with excessive SVG
    parameters.

  - Medium CVE-2013-0883: Bad read in Skia.

  - Low CVE-2013-0884: Inappropriate load of NaCl.

  - Medium CVE-2013-0885: Too many API permissions granted
    to web store

  - Medium CVE-2013-0886: Incorrect NaCl signal handling. 

  - Low CVE-2013-0887: Developer tools process has too many
    permissions and places too much trust in the connected
    server

  - Medium CVE-2013-0888: Out-of-bounds read in Skia

  - Low CVE-2013-0889: Tighten user gesture check for
    dangerous file downloads.

  - High CVE-2013-0890: Memory safety issues across the IPC
    layer.

  - High CVE-2013-0891: Integer overflow in blob handling.

  - Medium CVE-2013-0892: Lower severity issues across the
    IPC layer

  - Medium CVE-2013-0893: Race condition in media handling.

  - High CVE-2013-0894: Buffer overflow in vorbis decoding.

  - High CVE-2013-0895: Incorrect path handling in file
    copying.

  - High CVE-2013-0896: Memory management issues in plug-in
    message handling

  - Low CVE-2013-0897: Off-by-one read in PDF

  - High CVE-2013-0898: Use-after-free in URL handling

  - Low CVE-2013-0899: Integer overflow in Opus handling

  - Medium CVE-2013-0900: Race condition in ICU

  - Make adjustment for autodetecting of the PepperFlash
    library. The package with the PepperFlash hopefully will
    be soon available through packman

  - Update to 26.0.1411

  - Bug and stability fixes

  - Update to 26.0.1403

  - Bug and stability fixes

  - Using system libxml2 requires system libxslt.

  - Using system MESA does not work in i586 for some reason.

  - Also use system MESA, factory version seems adecuate
    now. 

  - Always use system libxml2.

  - Restrict the usage of system libraries instead of the
    bundled ones to new products, too much hassle otherwise.

  - Also link kerberos and libgps directly, do not dlopen
    them. 

  - Avoid using dlopen on system libraries, rpm or the
    package Manager do not handle this at all. tested for a
    few weeks and implemented with a macro so it can be
    easily disabled if problems arise.

  - Use SOME system libraries instead of the bundled ones,
    tested for several weeks and implemented with a macro
    for easy enable/Disable in case of trouble.

  - Update to 26.0.1393

  - Bug and stability fixes

  - Security fixes 

  - Update to 26.0.1375

  - Bug and stability fixes

  - Update to 26.0.1371

  - Bug and stability fixes

  - Update to 26.0.1367

  - Bug and stability fixes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804986"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/09");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-debuginfo-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-ffmpegsumo-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-ffmpegsumo-debuginfo-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-27.0.1425.0-1.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-debuginfo-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debuginfo-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debugsource-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-gnome-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-kde-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-debuginfo-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-27.0.1425.0-1.35.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-debuginfo-27.0.1425.0-1.35.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
