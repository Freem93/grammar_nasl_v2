#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-0420.
#

include("compat.inc");

if (description)
{
  script_id(57703);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/20 13:54:17 $");

  script_cve_id("CVE-2011-4885");
  script_bugtraq_id(51193);
  script_xref(name:"FEDORA", value:"2012-0420");

  script_name(english:"Fedora 15 : maniadrive-1.2-32.fc15.1 / php-5.3.9-1.fc15 / php-eaccelerator-0.9.6.1-9.fc15.1 (2012-0420)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Enhancements and Fixes in PHP 5.3.9 :

  - Added max_input_vars directive to prevent attacks based
    on hash collisions. (CVE-2011-4885)

    - Fixed bug #60150 (Integer overflow during the parsing
      of invalid exif header). (CVE-2011-4566)

Full upstream changelog : http://www.php.net/ChangeLog-5.php#5.3.9

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.3.9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=770823"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072488.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a53e36cb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072489.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ecd15e1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-January/072490.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bb971e5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected maniadrive, php and / or php-eaccelerator
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-eaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/27");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"maniadrive-1.2-32.fc15.1")) flag++;
if (rpm_check(release:"FC15", reference:"php-5.3.9-1.fc15")) flag++;
if (rpm_check(release:"FC15", reference:"php-eaccelerator-0.9.6.1-9.fc15.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / php / php-eaccelerator");
}
