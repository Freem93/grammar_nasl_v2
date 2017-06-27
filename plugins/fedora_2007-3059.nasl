#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-3059.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(28159);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 21:54:56 $");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_xref(name:"FEDORA", value:"2007-3059");

  script_name(english:"Fedora 7 : koffice-1.6.3-13.fc7 (2007-3059)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes fixes to pdf import filters that can cause
crashes possibly execute arbitrary code. See
http://www.kde.org/info/security/advisory-20071107-1.txt

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20071107-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=372591"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a713b3b3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kchart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kexi-driver-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kexi-driver-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:koffice-suite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/12");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"koffice-core-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-debuginfo-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-devel-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-filters-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-karbon-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kchart-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kexi-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kexi-driver-mysql-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kexi-driver-pgsql-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kformula-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kivio-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kplato-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kpresenter-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-krita-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kspread-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kugar-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-kword-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-libs-1.6.3-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"koffice-suite-1.6.3-13.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "koffice-core / koffice-debuginfo / koffice-devel / koffice-filters / etc");
}
