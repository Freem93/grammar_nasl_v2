#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-15472.
#

include("compat.inc");

if (description)
{
  script_id(56799);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/20 21:56:29 $");

  script_cve_id("CVE-2011-3646", "CVE-2011-4064");
  script_osvdb_id(76711);
  script_xref(name:"FEDORA", value:"2011-15472");

  script_name(english:"Fedora 14 : phpMyAdmin-3.4.7-1.fc14 (2011-15472)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes for 3.4.7.0 (2011-10-23);

  - [interface] Links in navigation when
    $cfg['MainPageIconic'] =3D false

    - [interface] Inline edit shows dropdowns even after
      closing

    - [view] View renaming did not work

    - [navi] Wrong icon for view (MySQL 5.5)

    - [doc] Missing documentation section

    - [pdf] Broken PDF file when exporting database to PDF

    - [core] Allow to set language in URL

    - [doc] Fix links to PHP documentation

    - [export] Export to bzip2 is not working

Changes for 3.4.6.0 (2011-10-16) :

  - [patch] InnoDB comment display with tooltips/aliases

    - [navi] Edit SQL statement after error

    - [interface] Collation not displayed for long enum
      fields

    - [export] Config for export compression not used

    - [privileges] DB-specific privileges won't submit

    - [config] Configuration storage incorrect suggested
      table name

    - [interface] Cannot execute saved query

    - [display] Full text button unchecks results display
      options

    - [display] Broken binary column when 'Show binary
      contents' is not set

    - [core] Call to undefined function PMA_isSuperuser()

    - [interface] Display options link missing after search

    - [core] CSP policy causing designer JS buttons to fail

    - [relation] Relations/constraints are dropped/created
      on every change

    - [display] Delete records from last page breaks search

    - [schema] PMA_User_Schema::processUserChoice() is
      broken

    - [core] External link fails in 3.4.5

    - [display] CharTextareaRows is not respected

    - [synchronize] Extraneous db choices

    - [security] Fixed local path disclosure vulnerability,
      see PMASA-2011-15=
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      11-15.php)

  - [security] Fixed XSS in setup (host/verbose parameter),
    see PMASA-2011-= 16
    (http://www.phpmyadmin.net/home_page/security/PMASA-2011
    -16.php)
    --------------------------------------------------------
    -------------------=

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-15.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-16.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=746880"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-November/069234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f737dee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"phpMyAdmin-3.4.7-1.fc14")) flag++;


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
