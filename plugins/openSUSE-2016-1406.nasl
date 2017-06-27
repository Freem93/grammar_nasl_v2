#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1406.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95560);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/12/06 14:24:42 $");

  script_name(english:"openSUSE Security Update : phpMyAdmin (openSUSE-2016-1406)");
  script_summary(english:"Check for the openSUSE-2016-1406 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to phpMyAdmin 4.4.15.9 fixes security issues and bugs.

The following security issues were fixed :

  - Unsafe generation of $cfg['blowfish_secret']
    (PMASA-2016-58)

  - phpMyAdmin's phpinfo functionality is removed
    (PMASA-2016-59)

  - AllowRoot and allow/deny rule bypass with specially
    crafted username (PMASA-2016-60)

  - Username matching weaknesses with allow/deny rules
    (PMASA-2016-61)

  - Possible to bypass logout timeout (PMASA-2016-62)

  - Full path disclosure (FPD) weaknesses (PMASA-2016-63)

  - Multiple XSS weaknesses (PMASA-2016-64)

  - Multiple denial-of-service (DOS) vulnerabilities
    (PMASA-2016-65)

  - Possible to bypass white-list protection for URL
    redirection (PMASA-2016-66)

  - BBCode injection to login page (PMASA-2016-67)

  - Denial-of-service (DOS) vulnerability in table
    partitioning (PMASA-2016-68)

  - Multiple SQL injection vulnerabilities (PMASA-2016-69 )

  - Incorrect serialized string parsing (PMASA-2016-70)

  - CSRF token not stripped from the URL (PMASA-2016-71)

The following bugfix changes are included :

  - Fix for expanding in navigation pane

  - Reintroduced a simplified version of PmaAbsoluteUri
    directive (needed with reverse proxies)

  - Fix editing of ENUM/SET/DECIMAL field structures

  - Improvements to the parser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012271"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/06");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"phpMyAdmin-4.4.15.9-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"phpMyAdmin-4.4.15.9-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"phpMyAdmin-4.4.15.9-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
