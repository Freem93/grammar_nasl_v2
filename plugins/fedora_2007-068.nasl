#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-068.
#

include("compat.inc");

if (description)
{
  script_id(24198);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:28 $");

  script_cve_id("CVE-2006-5072", "CVE-2006-6104");
  script_xref(name:"FEDORA", value:"2007-068");

  script_name(english:"Fedora Core 5 : mono-1.1.13.7-3.fc5.1 (2007-068)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security problem was found and fixed in mono class libraries that
affects the Mono web server implementation.

By appending spaces to URLs attackers could download the source code
of ASP.net scripts that would normally get executed by the web server.

After upgrading the packages you need to restart any running mono web
server.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-January/001244.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b5bc1c1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bytefx-data-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"bytefx-data-mysql-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"ibm-data-db2-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-basic-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-core-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-data-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-data-firebird-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-data-oracle-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-data-postgresql-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-data-sqlite-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-data-sybase-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-debuginfo-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-devel-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-extras-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-jscript-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-locale-extras-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-nunit-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-web-1.1.13.7-3.fc5.1")) flag++;
if (rpm_check(release:"FC5", reference:"mono-winforms-1.1.13.7-3.fc5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bytefx-data-mysql / ibm-data-db2 / mono-basic / mono-core / etc");
}
