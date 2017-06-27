#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-806.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91889);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-5701", "CVE-2016-5703", "CVE-2016-5705", "CVE-2016-5706", "CVE-2016-5730", "CVE-2016-5731", "CVE-2016-5733", "CVE-2016-5739");

  script_name(english:"openSUSE Security Update : phpMyAdmin (openSUSE-2016-806)");
  script_summary(english:"Check for the openSUSE-2016-806 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This phpMyAdmin update to version 4.4.15.7 fixes the following 
issues :

Issues fixed: Setup script doesn't use input type 'password' in all
relevant locations

Security issues fixed :

  - PMASA-2016-17 (CVE-2016-5701, CWE-661)
    https://www.phpmyadmin.net/security/PMASA-2016-17/

  - BBCode injection vulnerability

  - PMASA-2016-19 (CVE-2016-5703, CWE-661)
    https://www.phpmyadmin.net/security/PMASA-2016-19/

  - SQL injection attack

  - PMASA-2016-21 (CVE-2016-5705, CWE-661)
    https://www.phpmyadmin.net/security/PMASA-2016-21/

  - Multiple XSS vulnerabilities

  - PMASA-2016-22 (CVE-2016-5706, CWE-661)
    https://www.phpmyadmin.net/security/PMASA-2016-22/

  - DOS attack

  - PMASA-2016-23 (CVE-2016-5730, CWE-661)
    https://www.phpmyadmin.net/security/PMASA-2016-23/

  - Multiple full path disclosure vulnerabilities

  - PMASA-2016-24 (CVE-2016-5731, CWE-661)
    https://www.phpmyadmin.net/security/PMASA-2016-24/

  - XSS through FPD

  - PMASA-2016-26 (CVE-2016-5733, CWE-661)
    https://www.phpmyadmin.net/security/PMASA-2016-26/

  - Multiple XSS vulnerabilities

  - PMASA-2016-28 (CVE-2016-5739, CWE-661)
    https://www.phpmyadmin.net/security/PMASA-2016-28/

  - Referrer leak in transformations"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-17/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-19/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-21/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-22/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-23/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-24/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-26/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2016-28/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/29");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"phpMyAdmin-4.4.15.7-60.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
