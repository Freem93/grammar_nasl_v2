#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-7329.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(39603);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 22:50:38 $");

  script_cve_id("CVE-2009-2284");
  script_bugtraq_id(35543);
  script_xref(name:"FEDORA", value:"2009-7329");

  script_name(english:"Fedora 11 : phpMyAdmin-3.2.0.1-1.fc11 (2009-7329)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The first security release for phpMyAdmin 3.2.0: - [security] XSS:
Insufficient output sanitizing in bookmarks This version contains a
number of small new features and some bug fixes: - [core] better
support for vendor customisation (based on what Debian needs) - [rfe]
warn when session.gc_maxlifetime is less than cookie validity - [rfe]
configurable default charset for import - [rfe] link to InnoDB status
when error 150 occurs - [rfe] strip ` from column names on import -
[rfe] LeftFrameDBSeparator can be an array - [privileges] Extra back
reference when editing table-specific privileges - [display] Sortable
database columns - [lang] Wrong string in setup script hints -
[cleanup] XHTML cleanup, - [display] Possibility of disabling the
sliders - [privileges] Create user for existing database -
[privileges] Cleanup - [auth] AllowNoPasswordRoot error message is too
vague - [XHTML] View table headers/footers completely - [core] support
column name having square brackets

  - [lang] Lithuanian update - [auth] New setting
    AllowNoPassword (supercedes AllowNoPasswordRoot) that
    applies to all accounts (even the anonymous user) -
    [relation] Missing code with hashing for relationship
    editing - [rfe] Added option to disable mcrypt warning.
    - [bug] Request-URI Too Large error from Location header
    - [rfe] Check for relations support on main page. -
    [rfe] Explanation for using Host table. - [rfe] Link to
    download more themes. - [rfe] Add option to generate
    password on change password page. - [rfe] Allow logging
    of user status with Apache. - [patch] None default is
    different than other None in some languages. - [lang]
    Chinese Simplified update - [display] Sort arrows
    problem - [security] warn about existence of config
    directory on main page - [lang] Polish update - [export]
    Escape new line in CSV export - [patch] Optimizations
    for PHP loops - [import] SQL_MODE not saved during
    Partial Import - [auth] cache control missing (PHP-CGI)
    - [parser] Incorrect parsing of constraints in ALTER
    TABLE - [status] Server status - replication - [edit]
    Multi-row change with ']' improved - [rfe] Automatically
    copy generated password - [interface] Table with name
    'log_views' is incorrectly displayed as a view - [patch]
    Detect mcrypt initialization failure - [lang] Galician
    update

  - [lang] Swedish update - [lang] Norwegian update - [lang]
    Catalan update - [lang] Finnish update - [lang]
    Hungarian update

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=508879"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/026185.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?258404c5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"phpMyAdmin-3.2.0.1-1.fc11")) flag++;


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
