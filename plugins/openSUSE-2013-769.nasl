#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-769.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75170);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909", "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913", "CVE-2013-2914", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917", "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921", "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2924");
  script_bugtraq_id(62752, 62968);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2013:1556-1)");
  script_summary(english:"Check for the openSUSE-2013-769 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to Chromium 30.0.1599.66 :

  - Easier searching by image 

  - A number of new apps/extension APIs 

  - Lots of under the hood changes for stability and
    performance

  - Security fixes :

  + CVE-2013-2906: Races in Web Audio

  + CVE-2013-2907: Out of bounds read in Window.prototype
    object

  + CVE-2013-2908: Address bar spoofing related to the
    &ldquo;204 No Content&rdquo; status code

  + CVE-2013-2909: Use after free in inline-block rendering

  + CVE-2013-2910: Use-after-free in Web Audio

  + CVE-2013-2911: Use-after-free in XSLT

  + CVE-2013-2912: Use-after-free in PPAPI

  + CVE-2013-2913: Use-after-free in XML document parsing

  + CVE-2013-2914: Use after free in the Windows color
    chooser dialog

  + CVE-2013-2915: Address bar spoofing via a malformed
    scheme

  + CVE-2013-2916: Address bar spoofing related to the
    &ldquo;204 No Content&rdquo; status code

  + CVE-2013-2917: Out of bounds read in Web Audio

  + CVE-2013-2918: Use-after-free in DOM

  + CVE-2013-2919: Memory corruption in V8

  + CVE-2013-2920: Out of bounds read in URL parsing

  + CVE-2013-2921: Use-after-free in resource loader

  + CVE-2013-2922: Use-after-free in template element

  + CVE-2013-2923: Various fixes from internal audits,
    fuzzing and other initiatives 

  + CVE-2013-2924: Use-after-free in ICU. Upstream bug

  - Add patch chromium-fix-altgrkeys.diff 

  - Make sure that AltGr is treated correctly (issue#296835)

  - Do not build with system libxml (bnc#825157)

  - Update to Chromium 31.0.1640.0

  - Bug and Stability Fixes

  - Fix destkop file for chromium by removing extension from
    icon

  - Change the methodology for the Chromium packages. Build
    is now based on an official tarball. As soon as the Beta
    channel catches up with the current version, Chromium
    will be based on the Beta channel instead of svn
    snapshots

  - Update to 31.0.1632

  - Bug and Stability fixes

  - Added the flag --enable-threaded-compositing to the
    startup script. This flag seems to be required when
    hardware acceleration is in use. This prevents websites
    from locking up on users in certain cases.

  - Update to 31.0.1627

  - Bug and Stability fixes

  - Update to 31.0.1619

  - bug and Stability fixes

  - require mozilla-nss-devel >= 3.14 and mozilla-nspr-devel
    >= 4.9.5

  - Add patch exclude_ymp.diff to ensure that
    1-click-install files are downloaded and NOT opened
    (bnc#836059)

  - Update to 31.0.1611

  - Bug and stability fixes

  - Update to 31.0.1605

  - Bug and stability fixes

  - Change the startup script so that Chromium will not
    start when the chrome_sandbox doesn't have the SETUID.
    (bnc#779448)

  - Update to 31.0.1601

  - Bug and stability fixes

  - Update to 30.0.1594

  - Bug and stability fixes

  - Correct specfile to properly own /usr/bin/chromium
    (bnc#831584)

  - Chromium now expects the SUID-helper installed in the
    same directory as chromium. So let's create a symlink to
    the helper in /usr/lib

  - Update to 30.0.1587

  - Bug and stability fixes

  - Remove patch chromium-nss-compliant.diff (Upstream)

  - Update to 30.0.1575

  - Bug and stability fixes

  - Enable the gpu-sandbox again due to upstream fix
    (chromium#255063)

  - Update to 30.0.1567

  - bug and Stability fixes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00027.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836059"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/07");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-debuginfo-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debuginfo-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debugsource-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-gnome-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-kde-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-debuginfo-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-debuginfo-30.0.1599.66-1.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-debuginfo-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debuginfo-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debugsource-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-gnome-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-kde-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-debuginfo-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-30.0.1599.66-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-debuginfo-30.0.1599.66-1.11.2") ) flag++;

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
