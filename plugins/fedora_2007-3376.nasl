#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-3376.
#

include("compat.inc");

if (description)
{
  script_id(28216);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:54:56 $");

  script_cve_id("CVE-2007-5934");
  script_xref(name:"FEDORA", value:"2007-3376");

  script_name(english:"Fedora 8 : php-pear-MDB2-2.4.1-2.fc8 / php-pear-MDB2-Driver-mysql-1.4.1-3.fc8.1 / etc (2007-3376)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a security flaw CVE-2007-5934 with critical impact.
All users of php-pear-MDB2 are strongly advised to upgrade to these
updated packages.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=379081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=379101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=379131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=379161"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?193162f1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60b6ab75"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85627b05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php-pear-MDB2, php-pear-MDB2-Driver-mysql and / or
php-pear-MDB2-Driver-mysqli packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-MDB2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-MDB2-Driver-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-MDB2-Driver-mysqli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"php-pear-MDB2-2.4.1-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"php-pear-MDB2-Driver-mysql-1.4.1-3.fc8.1")) flag++;
if (rpm_check(release:"FC8", reference:"php-pear-MDB2-Driver-mysqli-1.4.1-3.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pear-MDB2 / php-pear-MDB2-Driver-mysql / etc");
}
