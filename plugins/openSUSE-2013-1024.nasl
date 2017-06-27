#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-1024.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74868);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5613", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6671", "CVE-2013-6673");
  script_osvdb_id(99710, 99711, 100806, 100807, 100808, 100812, 100813, 100815, 100816, 100818);

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-SU-2013:1957-1)");
  script_summary(english:"Check for the openSUSE-2013-1024 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to Thunderbird 24.2.0 (bnc#854370)

  - requires NSS 3.15.3.1 or higher

  - MFSA 2013-104/CVE-2013-5609/CVE-2013-5610 Miscellaneous
    memory safety hazards

  - MFSA 2013-108/CVE-2013-5616 (bmo#938341) Use-after-free
    in event listeners

  - MFSA 2013-109/CVE-2013-5618 (bmo#926361) Use-after-free
    during Table Editing

  - MFSA 2013-111/CVE-2013-6671 (bmo#930281) Segmentation
    violation when replacing ordered list elements

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

  - update to Thunderbird 24.1.1

  - requires NSPR 4.10.2 and NSS 3.15.3 for security reasons

  - fix binary compatibility issues for patch level updates
    (bmo#927073)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00119.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854370"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-24.2.0-49.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-24.2.0-49.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-24.2.0-49.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-24.2.0-49.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-24.2.0-49.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-24.2.0-49.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-24.2.0-49.63.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.6.0+24.2.0-49.63.1") ) flag++;

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
