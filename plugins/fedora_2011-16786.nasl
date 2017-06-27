#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-16786.
#

include("compat.inc");

if (description)
{
  script_id(57327);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:56:30 $");

  script_cve_id("CVE-2011-4634");
  script_xref(name:"FEDORA", value:"2011-16786");

  script_name(english:"Fedora 15 : phpMyAdmin-3.4.8-1.fc15 (2011-16786)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes for 3.4.8.0 (2011-12-01) :

  - [interface] enum data split at space char (more space to
    edit)

    - [interface] ENUM/SET editor can't handle commas in
      values

    - [interface] no links to browse/empty views and tables

    - [interface] Deleted search results remain visible

    - [import] ODS import ignores memory limits

    - [interface] Visual column separation

    - [parser] TRUE not recognized by parser

    - [config] Make location of php-gettext configurable

    - [import] Handle conflicts in some open_basedir
      situations

    - [display] Dropdown results - setting NULL does not
      work

    - [edit] Inline edit on multi-server configuration

    - [core] Notice: Array to string conversion in PHP 5.4

    - [interface] When ShowTooltipAliasTB is true, VIEW is
      wrongly shown as the view name in main panel db
      Structure page

    - [core] Fail to synchronize column with name of keyword

    - [interface] Add column after drop

    - [interface] Avoid showing the password in phpinfo()'s
      output

    - [GUI] 'newer version of phpMyAdmin' message not shown
      in IE8

    - [interface] Entering the key through a lookup window
      does not reset NULL

    - [security] Self-XSS on database names (synchronize,
      operations/rename), see PMASA-2011-18
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      11-18.php)

    - [security] Self-XSS on column type (create index,
      table Search), see PMASA-2011-18
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      11-18.php)

    - [security] Self-XSS on invalid query (table overview),
      see PMASA-2011-18
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      11-18.php)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-18.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=767666"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-December/071019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52702558"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/19");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"phpMyAdmin-3.4.8-1.fc15")) flag++;


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
