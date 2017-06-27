#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-518.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77432);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/29 14:08:53 $");

  script_cve_id("CVE-2014-4349", "CVE-2014-4955", "CVE-2014-4986", "CVE-2014-4987", "CVE-2014-5273", "CVE-2014-5274");

  script_name(english:"openSUSE Security Update : phpMyAdmin (openSUSE-SU-2014:1069-1)");
  script_summary(english:"Check for the openSUSE-2014-518 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This phpMyAdmin update addresses several security and non security
issues :

  - This is a phpMyAdmin version upgrade (bnc#892401): (From
    4.1.14.3) :

  - sf#4501 [security] XSS in table browse page
    (CVE-2014-5273)

  - sf#4502 [security] Self-XSS in enum value editor
    (CVE-2014-5273)

  - sf#4503 [security] Self-XSSes in monitor (CVE-2014-5273)

  - sf#4505 [security] XSS in view operations page
    (CVE-2014-5274)

  - sf#4504 [security] Self-XSS in query
    charts&#9;(CVE-2014-5273)

  - sf#4517 [security] XSS in relation view (CVE-2014-5273)
    (From 4.1.14.2) :

  - sf#4488 [security] XSS injection due to unescaped table
    name (triggers)(CVE-2014-4955)

  - sf#4492 [security] XSS in AJAX confirmation messages
    (CVE-2014-4986)

  - sf#4491 [security] Missing validation for accessing User
    groups feature (CVE-2014-4987) (From 4.1.14.1) :

  - sf#4464 [security] XSS injection due to unescaped
    db/table name in navigation hiding (CVE-2014-4349) (From
    4.1.14.0 through 4.1.9.0) :

  - Numerous non-security bugfixes are listed at
    https://github.com/phpmyadmin/phpmyadmin/blob/MAINT_4_1_
    14/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=892401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/phpmyadmin/phpmyadmin/blob/MAINT_4_1_14/ChangeLog"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/29");
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

if ( rpm_check(release:"SUSE12.3", reference:"phpMyAdmin-4.1.14.3-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"phpMyAdmin-4.1.14.3-8.1") ) flag++;

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
