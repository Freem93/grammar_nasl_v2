#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-717.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75148);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1705", "CVE-2013-1718", "CVE-2013-1722", "CVE-2013-1725", "CVE-2013-1730", "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737");
  script_osvdb_id(96014, 97388, 97389, 97390, 97391, 97392, 97398, 97401, 97404);

  script_name(english:"openSUSE Security Update : xulrunner17 (openSUSE-SU-2013:1496-1)");
  script_summary(english:"Check for the openSUSE-2013-717 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This xulrunner17 version update to 17.0.9esr fixes the following
security issues (bnc#840485) :

  - MFSA 2013-65/CVE-2013-1705 (bmo#882865) Buffer underflow
    when generating CRMF requests

  - MFSA 2013-76/CVE-2013-1718 Miscellaneous memory safety
    hazards

  - MFSA 2013-79/CVE-2013-1722 (bmo#893308) Use-after-free
    in Animation Manager during stylesheet cloning

  - MFSA 2013-82/CVE-2013-1725 (bmo#876762) Calling scope
    for new JavaScript objects can lead to memory corruption

  - MFSA 2013-88/CVE-2013-1730 (bmo#851353) Compartment
    mismatch re-attaching XBL-backed nodes

  - MFSA 2013-89/CVE-2013-1732 (bmo#883514) Buffer overflow
    with multi-column, lists, and floats

  - MFSA 2013-90/CVE-2013-1735/CVE-2013-1736 (bmo#898871,
    bmo#906301) Memory corruption involving scrolling

  - MFSA 2013-91/CVE-2013-1737 (bmo#907727) User-defined
    properties on DOM proxies get the wrong 'this' object"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840485"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xulrunner17 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/18");
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

if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-debuginfo-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-buildsymbols-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debuginfo-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debugsource-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-debuginfo-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-32bit-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-js-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-js-debuginfo-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-buildsymbols-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-debuginfo-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-debugsource-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-devel-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-devel-debuginfo-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xulrunner-32bit-17.0.9-2.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.9-2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-js / mozilla-js-32bit / mozilla-js-debuginfo / etc");
}
