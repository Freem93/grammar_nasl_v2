#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-65da02b95c.
#

include("compat.inc");

if (description)
{
  script_id(89801);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/18 16:52:29 $");

  script_cve_id("CVE-2016-2559", "CVE-2016-2560", "CVE-2016-2561", "CVE-2016-2562");
  script_xref(name:"FEDORA", value:"2016-65da02b95c");

  script_name(english:"Fedora 23 : php-udan11-sql-parser-3.4.0-1.fc23 / phpMyAdmin-4.5.5.1-1.fc23 (2016-65da02b95c)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin 4.5.5.1 (2016-02-29) =============================== This
release fixes multiple XSS vulnerabilities, please see PMASA-2016-10,
PMASA-2016-11, and PMASA-2016-12 for details; additionally it fixes a
vulnerability allowing man- in-the-middle attack on an API call to
GitHub, see PMASA-2016-13 for details. It also inclues fixes for the
following bugs: - issue #11971 CREATE UNIQUE INDEX index type is not
recognized by parser. - issue #11982 Row count wrong when grouping
joined tables. - issue #12012 Column definition with default value and
comment in CREATE TABLE exported faulty. - issue #12020 New statement
but no delimiter and unexpected token with REPLACE. - issue #12029
Fixed incorrect usage of SQL parser context in SQL export - issue
#12048 Fixed inclusion of gettext library from SQL parser

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1313221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1313224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1313695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1313696"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-March/178562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5846dba5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-March/178564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f797dc5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php-udan11-sql-parser and / or phpMyAdmin
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-udan11-sql-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"php-udan11-sql-parser-3.4.0-1.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"phpMyAdmin-4.5.5.1-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-udan11-sql-parser / phpMyAdmin");
}
