#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-429.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76135);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/19 10:50:24 $");

  script_cve_id("CVE-2014-3941", "CVE-2014-3942", "CVE-2014-3943");

  script_name(english:"openSUSE Security Update : typo3-cms-4_5 (openSUSE-SU-2014:0813-1)");
  script_summary(english:"Check for the openSUSE-2014-429 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"typo3-cms-4_5 was updated to version 4.5.34 to fix eight security
vulnerabilities and several other bugs.

These security problems where fixed :

  - Add trusted HTTP_HOST configuration (CVE-2014-3941)

  - XSS in (old) extension manager information function
    (CVE-2014-3943)

  - XSS in new content element wizard (CVE-2014-3943)

  - XSS in template tools on root page (CVE-2014-3943)

  - XSS in Backend Layout Wizard (CVE-2014-3943)

  - Encode URL for use in JavaScript (CVE-2014-3943)

  - Fix insecure unserialize in colorpicker (CVE-2014-3942)

  - Remove charts.swf to get rid of XSS vulnerability
    (CVE-2014-3943)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-06/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881282"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected typo3-cms-4_5 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typo3-cms-4_5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"typo3-cms-4_5-4.5.34-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"typo3-cms-4_5-4.5.34-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "typo3-cms-4_5");
}
