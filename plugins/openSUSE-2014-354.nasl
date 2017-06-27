#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-354.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75352);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-1492", "CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1522", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1528", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");

  script_name(english:"openSUSE Security Update : seamonkey (openSUSE-SU-2014:0629-1)");
  script_summary(english:"Check for the openSUSE-2014-354 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a SeaMonkey update to version 2.26 :

  - MFSA 2014-34/CVE-2014-1518/CVE-2014-1519 Miscellaneous
    memory safety hazards

  - MFSA 2014-36/CVE-2014-1522 (bmo#995289) Web Audio memory
    corruption issues

  - MFSA 2014-37/CVE-2014-1523 (bmo#969226) Out of bounds
    read while decoding JPG images

  - MFSA 2014-38/CVE-2014-1524 (bmo#989183) Buffer overflow
    when using non-XBL object as XBL

  - MFSA 2014-39/CVE-2014-1525 (bmo#989210) Use-after-free
    in the Text Track Manager for HTML video

  - MFSA 2014-41/CVE-2014-1528 (bmo#963962) Out-of-bounds
    write in Cairo

  - MFSA 2014-42/CVE-2014-1529 (bmo#987003) Privilege
    escalation through Web Notification API

  - MFSA 2014-43/CVE-2014-1530 (bmo#895557) Cross-site
    scripting (XSS) using history navigations

  - MFSA 2014-44/CVE-2014-1531 (bmo#987140) Use-after-free
    in imgLoader while resizing images

  - MFSA 2014-45/CVE-2014-1492 (bmo#903885) Incorrect IDNA
    domain name matching for wildcard certificates (fixed by
    NSS 3.16)

  - MFSA 2014-46/CVE-2014-1532 (bmo#966006) Use-after-free
    in nsHostResolver

  - MFSA 2014-47/CVE-2014-1526 (bmo#988106) Debugger can
    bypass XrayWrappers with JavaScript

  - rebased patches

  - added aarch64 porting patches

  - mozilla-aarch64-bmo-810631.patch

  - mozilla-aarch64-bmo-962488.patch

  - mozilla-aarch64-bmo-963023.patch

  - mozilla-aarch64-bmo-963024.patch

  - mozilla-aarch64-bmo-963027.patch

  - requires NSPR 4.10.3 and NSS 3.16

  - added mozilla-icu-strncat.patch to fix post build checks"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875378"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/02");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-2.26-1.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debuginfo-2.26-1.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debugsource-2.26-1.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-dom-inspector-2.26-1.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-irc-2.26-1.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-common-2.26-1.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-other-2.26-1.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-venkman-2.26-1.45.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-2.26-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debuginfo-2.26-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debugsource-2.26-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-dom-inspector-2.26-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-irc-2.26-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-common-2.26-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-other-2.26-20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-venkman-2.26-20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-debuginfo / seamonkey-debugsource / etc");
}
