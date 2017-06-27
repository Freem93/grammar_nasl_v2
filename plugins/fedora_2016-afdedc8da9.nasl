#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-afdedc8da9.
#

include("compat.inc");

if (description)
{
  script_id(90842);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/18 17:03:06 $");

  script_cve_id("CVE-2016-1926");
  script_xref(name:"FEDORA", value:"2016-afdedc8da9");

  script_name(english:"Fedora 23 : openvas-cli-1.4.4-1.fc23 / openvas-gsa-6.0.10-3.fc23 / openvas-libraries-8.0.7-2.fc23 / etc (2016-afdedc8da9)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bump to latest upstream bugfix releases. Contains Security fix for
CVE-2016-1926

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1300683"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/183367.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b77a53f1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/183368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d600bae4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/183369.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc8e7472"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/183370.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c61ca5c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-May/183371.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?222ba6e2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-gsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvas-scanner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");
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
if (rpm_check(release:"FC23", reference:"openvas-cli-1.4.4-1.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"openvas-gsa-6.0.10-3.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"openvas-libraries-8.0.7-2.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"openvas-manager-6.0.8-2.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"openvas-scanner-5.0.5-3.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvas-cli / openvas-gsa / openvas-libraries / openvas-manager / etc");
}
