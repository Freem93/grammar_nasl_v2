#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-776.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80049);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/16 15:17:31 $");

  script_cve_id("CVE-2014-9218", "CVE-2014-9219");

  script_name(english:"openSUSE Security Update : phpMyAdmin (openSUSE-SU-2014:1636-1)");
  script_summary(english:"Check for the openSUSE-2014-776 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin on openSUSE 12.3 and 13.1 was updated to 4.1.14.8. This
update fixes one vulnerability.

  - Security fixes :

  - PMASA-2014-17 (CVE-2014-9218, CWE-661 CWE-400)
    [boo#908363]
    http://www.phpmyadmin.net/home_page/security/PMASA-2014-
    17.php

  - sf#4611 [security] DOS attack with long passwords

phpMyAdmin on openSUSE 13.2 was updated to 4.2.13.1 (2014-12-03)

  - Security fixes :

  - PMASA-2014-18 (CVE-2014-9219, CWE-661 CWE-79)
    [boo#908364]
    http://www.phpmyadmin.net/home_page/security/PMASA-2014-
    18.php

  - sf#4612 [security] XSS vulnerability in redirection
    mechanism

  - PMASA-2014-17 (CVE-2014-9218, CWE-661 CWE-400)
    [boo#908363]
    http://www.phpmyadmin.net/home_page/security/PMASA-2014-
    17.php

  - sf#4611 [security] DOS attack with long passwords

  - Bugfixes :

  - sf#4604 Query history not being deleted

  - sf#4057 db/table query string parameters no longer work

  - sf#4605 Unseen messages in tracking

  - sf#4606 Tracking report export as SQL dump does not work

  - sf#4607 Syntax error during db_copy operation

  - sf#4608 SELECT permission issues with relations and
    restricted access"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-17.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-18.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908364"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/16");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"phpMyAdmin-4.1.14.8-1.38.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"phpMyAdmin-4.1.14.8-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"phpMyAdmin-4.2.13.1-8.1") ) flag++;

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
