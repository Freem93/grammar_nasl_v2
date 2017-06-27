#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-197.
#

include("compat.inc");

if (description)
{
  script_id(24301);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:54:54 $");

  script_xref(name:"FEDORA", value:"2007-197");

  script_name(english:"Fedora Core 6 : postgresql-8.1.7-1.fc6 (2007-197)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Sun Feb 4 2007 Tom Lane <tgl at redhat.com> 8.1.7-1

    - Update to PostgreSQL 8.1.7 to fix CVE-2007-0555,
      CVE-2007-0556 Related: #225496

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7f77c04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"postgresql-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-contrib-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-debuginfo-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-devel-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-docs-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-libs-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-pl-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-python-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-server-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-tcl-8.1.7-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"postgresql-test-8.1.7-1.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
}
