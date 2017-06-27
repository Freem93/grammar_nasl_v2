#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-e6651efbaf.
#

include("compat.inc");

if (description)
{
  script_id(90229);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/04 15:55:09 $");

  script_cve_id("CVE-2016-0763");
  script_xref(name:"FEDORA", value:"2016-e6651efbaf");

  script_name(english:"Fedora 22 : tomcat-7.0.68-3.fc22 (2016-e6651efbaf)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Revert sysconfig migration changes, resolves:
    rhbz#1311771, rhbz#1311905 - Add /etc/tomcat/conf.d/
    with shell expansion support, resolves rhbz#1293636 ----
    - Load sysconfig from tomcat.conf, resolves:
    rhbz#1311771, rhbz#1311905 - Set default
    javax.sql.DataSource factory to apache commons one,
    resolves rhbz#1214381 ---- - Updated to 7.0.68 - Fix
    symlinks from $CATALINA_HOME/lib perspective, resolves:
    rhbz#1308685 - Fix tomcat user shell, resolves
    rhbz#1302718 - Remove log4j support. It has never been
    working actually. See rhbz#1236297 - Move shipped config
    to /etc/sysconfig/tomcat. /etc/tomcat/tomcat.conf can
    now be used to override it with shell expansion,
    resolves rhbz#1293636 - Security fix for CVE-2016-0763

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1311093"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-March/179356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18ada123"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/28");
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
if (rpm_check(release:"FC22", reference:"tomcat-7.0.68-3.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat");
}
