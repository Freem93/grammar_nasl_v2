#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-4212.
#

include("compat.inc");

if (description)
{
  script_id(47341);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:24:18 $");

  script_bugtraq_id(38182, 38430, 38431);
  script_osvdb_id(62582, 62583, 63078);
  script_xref(name:"FEDORA", value:"2010-4212");

  script_name(english:"Fedora 12 : maniadrive-1.2-21.fc12 / php-5.3.2-1.fc12 (2010-4212)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a maintenance release in the 5.3 series, which includes a
large number of bug fixes. Security Enhancements and Fixes in PHP
5.3.2: - Improved LCG entropy. (Rasmus, Samy Kamkar) - Fixed safe_mode
validation inside tempnam() when the directory path does not end with
a /). (Martin Jansen) - Fixed a possible open_basedir/safe_mode bypass
in the session extension identified by Grzegorz Stachowiak. (Ilia) Key
Bug Fixes in PHP 5.3.2 include: - Added support for SHA-256 and
SHA-512 to php's crypt. - Added protection for $_SESSION from
interrupt corruption and improved 'session.save_path' check. - Fixed
bug #51059 (crypt crashes when invalid salt are given). - Fixed bug
#50940 Custom content-length set incorrectly in Apache sapis. - Fixed
bug #50847 (strip_tags() removes all tags greater then 1023 bytes
long). - Fixed bug #50723 (Bug in garbage collector causes crash). -
Fixed bug #50661 (DOMDocument::loadXML does not allow UTF-16). - Fixed
bug #50632 (filter_input() does not return default value if the
variable does not exist).

  - Fixed bug #50540 (Crash while running
    ldap_next_reference test cases). - Fixed bug #49851
    (http wrapper breaks on 1024 char long headers). - Over
    60 other bug fixes. Full upstream changelog:
    http://www.php.net/ChangeLog-5.php#5.3.2

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.3.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=570769"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-March/038059.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bfe0751"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-March/038060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b126b0ff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected maniadrive and / or php packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC12", reference:"maniadrive-1.2-21.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"php-5.3.2-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / php");
}
