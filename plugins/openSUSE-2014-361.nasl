#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-361.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75357);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_bugtraq_id(67123, 67126, 67129, 67130, 67131, 67134, 67135, 67137);

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-SU-2014:0640-1)");
  script_summary(english:"Check for the openSUSE-2014-361 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a MozillaThunderbird update to version 24.5.0 :

  - MFSA 2014-34/CVE-2014-1518 Miscellaneous memory safety
    hazards

  - MFSA 2014-37/CVE-2014-1523 (bmo#969226) Out of bounds
    read while decoding JPG images

  - MFSA 2014-38/CVE-2014-1524 (bmo#989183) Buffer overflow
    when using non-XBL object as XBL

  - MFSA 2014-42/CVE-2014-1529 (bmo#987003) Privilege
    escalation through Web Notification API

  - MFSA 2014-43/CVE-2014-1530 (bmo#895557) Cross-site
    scripting (XSS) using history navigations

  - MFSA 2014-44/CVE-2014-1531 (bmo#987140) Use-after-free
    in imgLoader while resizing images

  - MFSA 2014-46/CVE-2014-1532 (bmo#966006) Use-after-free
    in nsHostResolver

  - use shipped-locales as the authoritative source for
    supported locales (some unsupported locales disappear
    from -other package)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875378"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
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

if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-buildsymbols-24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debuginfo-24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debugsource-24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-common-24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-other-24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-1.6.0+24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-debuginfo-1.6.0+24.5.0-61.47.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-24.5.0-70.19.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-24.5.0-70.19.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-24.5.0-70.19.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-24.5.0-70.19.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-24.5.0-70.19.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-24.5.0-70.19.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-24.5.0-70.19.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"enigmail-1.6.0+24.5.0-70.19.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"enigmail-debuginfo-1.6.0+24.5.0-70.19.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
