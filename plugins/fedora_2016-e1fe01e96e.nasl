#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-e1fe01e96e.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(89625);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/18 17:03:07 $");

  script_cve_id("CVE-2016-1927", "CVE-2016-2038", "CVE-2016-2039", "CVE-2016-2040", "CVE-2016-2041", "CVE-2016-2042", "CVE-2016-2043", "CVE-2016-2044", "CVE-2016-2045");
  script_xref(name:"FEDORA", value:"2016-e1fe01e96e");

  script_name(english:"Fedora 22 : phpMyAdmin-4.5.4-1.fc22 (2016-e1fe01e96e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin 4.5.4 (2016-01-28) ============================= - live
data edit of big sets is not working - Table list not saved in db QBE
bookmarked search - While 'changing a column', query fails with a
syntax error after the 'CHARSET=' keyword - Avoid syntax error in
JavaScript messages on invalid PHP setting for max_input_vars -
Properly handle errors in upacking zip archive - Set PHP's internal
encoding to UTF-8 - Fixed Kanji encoding in some specific cases -
Check whether iconv works before using it - Avoid conversion of MySQL
error messages - Undefined index: parameters - Undefined index:
field_name_orig - Undefined index: host - 'Add to central columns'
(per column button) does nothing - SQL duplicate entry error trying to
INSERT in designer_settings table - Fix handling of databases with dot
in a name - Fix hiding of page content behind menu - FROM clause not
generated after loading search bookmark - Fix creating/editing VIEW
with DEFINER containing special chars - Do not invoke FLUSH PRIVILEGES
when server in --skip-grant-tables - Misleading message for
configuration storage - Table pagination does nothing when session
expired - Index comments not working properly - Better handle local
storage errors - Improve detection of privileges for privilege
adjusting - Undefined property: stdClass::$releases at version check
when disabled in config - SQL comment and variable stripped from
bookmark on save - Gracefully handle errors in regex based JavaScript
search - [Security] Multiple full path disclosure vulnerabilities, see
PMASA-2016-1 - [Security] Unsafe generation of CSRF token, see
PMASA-2016-2 - [Security] Multiple XSS vulnerabilities, see
PMASA-2016-3 - [Security] Insecure password generation in JavaScript,
see PMASA-2016-4 - [Security] Unsafe comparison of CSRF token, see
PMASA-2016-5 - [Security] Multiple full path disclosure
vulnerabilities, see PMASA-2016-6 - [Security] XSS vulnerability in
normalization page, see PMASA-2016-7 - [Security] Full path disclosure
vulnerability in SQL parser, see PMASA-2016-8 - [Security] XSS
vulnerability in SQL editor, see PMASA-2016-9

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302686"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/176483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f479b586"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"phpMyAdmin-4.5.4-1.fc22")) flag++;


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
