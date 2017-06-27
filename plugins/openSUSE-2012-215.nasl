#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-215.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74592);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2011-3057", "CVE-2011-3058", "CVE-2011-3059", "CVE-2011-3060", "CVE-2011-3061", "CVE-2011-3062", "CVE-2011-3063", "CVE-2011-3064", "CVE-2011-3065");
  script_osvdb_id(80604, 80736, 80737, 80738, 80739, 80740, 80741, 80742, 80743);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2012:0492-1)");
  script_summary(english:"Check for the openSUSE-2012-215 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security update for Chromium and V8 to 18.0.1025.142.

Following bugs are listed in the Chrome changelog :

  - [$500]
    [109574<https://code.google.com/p/chromium/issues/detail
    ?id=109574>] Medium CVE-2011-3058: Bad interaction
    possibly leading to XSS in EUC-JP. Credit to Masato
    Kinugawa.

  - [$500]
    [112317<https://code.google.com/p/chromium/issues/detail
    ?id=112317>] Medium CVE-2011-3059: Out-of-bounds read in
    SVG text handling. Credit to Arthur Gerkis.

  - [$500]
    [114056<https://code.google.com/p/chromium/issues/detail
    ?id=114056>] Medium CVE-2011-3060: Out-of-bounds read in
    text fragment handling. Credit to miaubiz.

  - [116398
    <https://code.google.com/p/chromium/issues/detail?id=116
    398>] Medium CVE-2011-3061: SPDY proxy certificate
    checking error. Credit to Leonidas Kontothanassis of
    Google.

  - [116524
    <https://code.google.com/p/chromium/issues/detail?id=116
    524>] High CVE-2011-3062: Off-by-one in OpenType
    Sanitizer. Credit to Mateusz Jurczyk of the Google
    Security Team.

  - [117417
    <https://code.google.com/p/chromium/issues/detail?id=117
    417>] Low CVE-2011-3063: Validate navigation requests
    from the renderer more carefully. Credit to kuzzcc,
    Sergey Glazunov, PinkiePie and scarybeasts (Google
    Chrome Security Team).

  - [$1000]
    [117471<https://code.google.com/p/chromium/issues/detail
    ?id=117471>] High CVE-2011-3064: Use-after-free in SVG
    clipping. Credit to Atte Kettunen of OUSPG.

  - [$1000]
    [117588<https://code.google.com/p/chromium/issues/detail
    ?id=117588>] High CVE-2011-3065: Memory corruption in
    Skia. Credit to Omair.

  - [$500]
    [117794<https://code.google.com/p/chromium/issues/detail
    ?id=117794>] Medium CVE-2011-3057: Invalid read in v8.
    Credit to Christian Holler.

The bugs
[112317<https://code.google.com/p/chromium/issues/detail?id=112317>],
[114056 <https://code.google.com/p/chromium/issues/detail?id=114056>]
and [ 117471
<https://code.google.com/p/chromium/issues/detail?id=117471>] were
detected using
AddressSanitizer<http://code.google.com/p/address-sanitizer/wiki/Addre
ssSanitizer> .

We'd also like to thank miaubiz, Chamal de Silva, Atte Kettunen of
OUSPG, Aki Helin of OUSPG and Arthur Gerkis for working with us during
the development cycle and preventing security regressions from ever
reaching the stable channel. $8000 of additional rewards were issued
for this awesomeness"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://code.google.com/p/address-sanitizer/wiki/AddressSanitizer"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-04/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=109574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=112317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=114056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=116398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=116524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=117417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=117471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=117588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=117794"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
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

if ( rpm_check(release:"SUSE12.1", reference:"chromium-20.0.1094.0-1.17.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-20.0.1094.0-1.17.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-20.0.1094.0-1.17.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-20.0.1094.0-1.17.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-20.0.1094.0-1.17.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-20.0.1094.0-1.17.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-20.0.1094.0-1.17.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-3.10.0.5-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-debuginfo-3.10.0.5-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-debugsource-3.10.0.5-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-devel-3.10.0.5-1.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-private-headers-devel-3.10.0.5-1.21.1") ) flag++;

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
