#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-6ab2d29fba.
#

include("compat.inc");

if (description)
{
  script_id(90376);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/04/07 16:01:44 $");

  script_xref(name:"FEDORA", value:"2016-6ab2d29fba");

  script_name(english:"Fedora 24 : nodejs-5.10.0-1.fc24 / nodejs-bl-1.1.2-1.fc24 / nodejs-buffertools-2.1.3-12.fc24 / etc (2016-6ab2d29fba)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update Node.js to the 5.x stable branch This update also includes a
fix for a man-in-the-middle vulnerability in npm.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1300103"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181409.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b36fd7c0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?272e6efc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e86096b3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e67c617c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?517116aa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5298247b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181415.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c5e0c9b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181416.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e088a9c2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181417.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2a16640"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7928b9e2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cd9f121"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181420.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?475c2002"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99b1d915"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af87ffd0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/181423.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?129adc5f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-bl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-buffertools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-fs-ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-gdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-i2c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-libxmljs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-mapnik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-node-expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-node-stringprep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-request");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-srs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs-zipfile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC24", reference:"nodejs-5.10.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-bl-1.1.2-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-buffertools-2.1.3-12.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-fs-ext-0.5.0-9.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-gdal-0.9.0-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-i2c-0.2.1-6.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-iconv-2.1.11-8.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-libxmljs-0.17.1-4.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-mapnik-3.5.6-2.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-node-expat-2.3.11-8.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-node-stringprep-0.7.3-9.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-request-2.67.0-6.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-sqlite3-3.1.2-3.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-srs-1.1.0-3.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"nodejs-zipfile-0.5.9-7.fc24")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / nodejs-bl / nodejs-buffertools / nodejs-fs-ext / etc");
}
