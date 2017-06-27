#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-13065.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43121);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2009-4297", "CVE-2009-4298", "CVE-2009-4299", "CVE-2009-4300", "CVE-2009-4301", "CVE-2009-4302", "CVE-2009-4303", "CVE-2009-4304", "CVE-2009-4305");
  script_xref(name:"FEDORA", value:"2009-13065");

  script_name(english:"Fedora 12 : moodle-1.9.7-1.fc12 (2009-13065)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Moodle upstream has released latest stable versions (1.9.7 and
1.8.11), fixing multiple security issues. The list for 1.9.7 release:
-------------------------- Security issues * MSA-09-0022 - Multiple
CSRF problems fixed * MSA-09-0023 - Fixed user account disclosure in
LAMS module * MSA-09-0024 - Fixed insufficient access control in
Glossary module

  - MSA-09-0025 - Unneeded MD5 hashes removed from user
    table * MSA-09-0026 - Fixed invalid application access
    control in MNET interface * MSA-09-0027 - Ensured login
    information is always sent secured when using SSL for
    logins * MSA-09-0028 - Passwords and secrets are no
    longer ever saved in backups, new backup capabilities
    moodle/backup:userinfo and moodle/restore:userinfo for
    controlling who can backup/restore user data, new checks
    in the security overview report help admins identify
    dangerous backup permissions * MSA-09-0029 - A strong
    password policy is now enabled by default, enabling
    password salt in encouraged in config.php, admins are
    forced to change password after the upgrade and admins
    can force password change on other users via Bulk user
    actions * MSA-09-0030 - New detection of insecure Flash
    player plugins, Moodle won't serve Flash to insecure
    plugins * MSA-09-0031 - Fixed SQL injection in SCORM
    module The list for 1.8.11 release:
    ---------------------------- Security issues *
    MSA-09-0022 - Multiple CSRF problems fixed * MSA-09-0023
    - Fixed user account disclosure in LAMS module *
    MSA-09-0024 - Fixed insufficient access control in
    Glossary module * MSA-09-0025 - Unneeded MD5 hashes
    removed from user table * MSA-09-0026 - Fixed invalid
    application access control in MNET interface *
    MSA-09-0027 - Ensured login information is always sent
    secured when using SSL for logins * MSA-09-0028 -
    Passwords and secrets are no longer ever saved in
    backups, new backup capabilities moodle/backup:userinfo
    and moodle/restore:userinfo for controlling who can
    backup/restore user data * MSA-09-0029 - Enabling a
    password salt in encouraged in config.php and admins are
    forced to change password after the upgrade *
    MSA-09-0031 - Fixed SQL injection in SCORM module
    References: -----------
    http://docs.moodle.org/en/Moodle_1.9.7_release_notes
    http://docs.moodle.org/en/Moodle_1.8.11_release_notes
    CVE Request: ------------
    http://www.openwall.com/lists/oss-security/2009/12/06/1

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.moodle.org/en/Moodle_1.8.11_release_notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.moodle.org/en/Moodle_1.9.7_release_notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2009/12/06/1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=544766"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032539.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c9a6869"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected moodle package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(89, 200, 255, 264, 310, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"moodle-1.9.7-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moodle");
}
