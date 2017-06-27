#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-994.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75240);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5611", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-5619", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673");
  script_osvdb_id(99710, 99711, 100805, 100806, 100807, 100808, 100809, 100810, 100811, 100812, 100813, 100814, 100815, 100816, 100818);

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2013:1917-1)");
  script_summary(english:"Check for the openSUSE-2013-994 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to Firefox 26.0 (bnc#854367, bnc#854370)

  - rebased patches

  - requires NSPR 4.10.2 and NSS 3.15.3.1

  - MFSA 2013-104/CVE-2013-5609/CVE-2013-5610 Miscellaneous
    memory safety hazards

  - MFSA 2013-105/CVE-2013-5611 (bmo#771294) Application
    Installation doorhanger persists on navigation

  - MFSA 2013-106/CVE-2013-5612 (bmo#871161) Character
    encoding cross-origin XSS attack

  - MFSA 2013-107/CVE-2013-5614 (bmo#886262) Sandbox
    restrictions not applied to nested object elements

  - MFSA 2013-108/CVE-2013-5616 (bmo#938341) Use-after-free
    in event listeners

  - MFSA 2013-109/CVE-2013-5618 (bmo#926361) Use-after-free
    during Table Editing

  - MFSA 2013-110/CVE-2013-5619 (bmo#917841) Potential
    overflow in JavaScript binary search algorithms

  - MFSA 2013-111/CVE-2013-6671 (bmo#930281) Segmentation
    violation when replacing ordered list elements

  - MFSA 2013-112/CVE-2013-6672 (bmo#894736) Linux clipboard
    information disclosure though selection paste

  - MFSA 2013-113/CVE-2013-6673 (bmo#970380) Trust settings
    for built-in roots ignored during EV certificate
    validation

  - MFSA 2013-114/CVE-2013-5613 (bmo#930381, bmo#932449)
    Use-after-free in synthetic mouse movement

  - MFSA 2013-115/CVE-2013-5615 (bmo#929261) GetElementIC
    typed array stubs can be generated outside observed
    typesets

  - MFSA 2013-116/CVE-2013-6629/CVE-2013-6630 (bmo#891693)
    JPEG information leak

  - MFSA 2013-117 (bmo#946351) Mis-issued ANSSI/DCSSI
    certificate (fixed via NSS 3.15.3.1)

  - removed gecko.js preference file as GStreamer is enabled
    by default now"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854370"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/13");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-26.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-26.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-26.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-26.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-26.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-26.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-26.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-26.0-1.43.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
