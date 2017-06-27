#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1022.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93213);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/09/01 13:14:19 $");

  script_cve_id("CVE-2013-7073", "CVE-2014-9508", "CVE-2015-2047");

  script_name(english:"openSUSE Security Update : typo3-cms-4_5 (openSUSE-2016-1022)");
  script_summary(english:"Check for the openSUSE-2016-1022 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for typo3-cms-4_5 fixes the following issues :

  - CVE-2015-2047: Authentication Bypass
    (TYPO3-CORE-SA-2015-001)

  - CVE-2014-9508: Link spoofing and cache poisoning
    (TYPO3-CORE-SA-2014-003)

  - TYPO3-CORE-SA-2014-002: Multiple Vulnerabilities

  - CVE-2013-7073: Multiple vulnerabilities
    (TYPO3-CORE-SA-2013-004) This update contains the last
    upstream release 4.5.40, LTS discontinued since 04.2015."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected typo3-cms-4_5 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typo3-cms-4_5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"typo3-cms-4_5-4.5.40-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"typo3-cms-4_5-4.5.40-7.1") ) flag++;

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
