#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-11428.
#

include("compat.inc");

if (description)
{
  script_id(48411);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_cve_id("CVE-2010-1914", "CVE-2010-1915", "CVE-2010-1917", "CVE-2010-2190", "CVE-2010-2225");
  script_bugtraq_id(38708, 40948, 41991);
  script_xref(name:"FEDORA", value:"2010-11428");

  script_name(english:"Fedora 12 : maniadrive-1.2-22.fc12 / php-5.3.3-1.fc12 / php-eaccelerator-0.9.6.1-2.fc12 (2010-11428)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to PHP 5.3.3 Security Enhancements and Fixes in PHP 5.3.3: *
Rewrote var_export() to use smart_str rather than output buffering,
prevents data disclosure if a fatal error occurs (CVE-2010-2531). *
Fixed a possible resource destruction issues in shm_put_var(). * Fixed
a possible information leak because of interruption of XOR operator. *
Fixed a possible memory corruption because of unexpected call-time
pass by refernce and following memory clobbering through callbacks. *
Fixed a possible memory corruption in ArrayObject::uasort(). * Fixed a
possible memory corruption in parse_str(). * Fixed a possible memory
corruption in pack(). * Fixed a possible memory corruption in
substr_replace(). * Fixed a possible memory corruption in
addcslashes(). * Fixed a possible stack exhaustion inside fnmatch(). *
Fixed a possible dechunking filter buffer overflow. * Fixed a possible
arbitrary memory access inside sqlite extension. * Fixed string format
validation inside phar extension. * Fixed handling of session variable
serialization on certain prefix characters. * Fixed a NULL pointer
dereference when processing invalid XML-RPC requests (Fixes
CVE-2010-0397, bug #51288). * Fixed SplObjectStorage unserialization
problems (CVE-2010-2225). * Fixed possible buffer overflows in
mysqlnd_list_fields, mysqlnd_change_user. * Fixed possible buffer
overflows when handling error packets in mysqlnd. Full upstream
Changelog: http://www.php.net/ChangeLog-5.php#5.3.3

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.3.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=601897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=605641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=617180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=617211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=617232"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/046046.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?207c9d7f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/046047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d159d4b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/046048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6afce4cd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected maniadrive, php and / or php-eaccelerator
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-eaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/24");
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
if (rpm_check(release:"FC12", reference:"maniadrive-1.2-22.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"php-5.3.3-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"php-eaccelerator-0.9.6.1-2.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / php / php-eaccelerator");
}
