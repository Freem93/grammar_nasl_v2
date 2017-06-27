#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-15725.
#

include("compat.inc");

if (description)
{
  script_id(62726);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:27:58 $");

  script_bugtraq_id(55925, 55939);
  script_xref(name:"FEDORA", value:"2012-15725");

  script_name(english:"Fedora 16 : phpMyAdmin-3.5.3-1.fc16 (2012-15725)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin 3.5.3.0 (2012-10-08) ===============================

  - [interface] Browse mode 'Show' button gives blank page
    if no results anymore

    - [interface] Copy Database Ajax feedback vanishes long
      before copying is done

    - [interface] GC-maxlifetime warning incorrectly
      displayed

    - [interface] Search fails with JS error when tooltips
      disabled

    - [interface] Event comments not saved

    - [edit] Can't enter date directly when editing inline

    - [interface] Inline query editor doesn't work from
      search results

    - [edit] BLOB download no longer works

    - [config] Error in generated configuration arrray

    - [GUI] Invalid HTML code in multi submits confirmation
      form

    - [interface] Designer sometimes places tables on the
      top menu

    - [core] Call to undefined function __() when config
      file has wrong permissions

    - [edit] Error searching table with many fields

    - [edit] Cannot copy a DB with table and views

    - [privileges] Incorrect updating of the list of users

    - [edit] cell edit date field with empty date fills in
      current date

    - [edit] current_date from function drop down fails on
      update

    - [compatibility] add support for Solaris and FreeBSD
      system load and memory display in server status

    - [import] Table import from XML file fails

    - [display] replace Highcharts with jqplot for Display
      chart

    - [edit] Pasting value doesn't clear null checkbox

    - [edit] Datepicker for date and datetime fields is
      broken

    - [security] Unspecified minor security fix by upstream,
      see PMASA-2012-6
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      12-6.php)

    - [security] Unspecified minor security fix by upstream,
      see PMASA-2012-7
      (http://www.phpmyadmin.net/home_page/security/PMASA-20
      12-7.php)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-6.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-7.php"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-October/090826.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f940b8da"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"phpMyAdmin-3.5.3-1.fc16")) flag++;


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
