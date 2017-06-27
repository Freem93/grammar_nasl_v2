#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3379.
#

include("compat.inc");

if (description)
{
  script_id(32101);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:13:39 $");

  script_cve_id("CVE-2008-1670");
  script_xref(name:"FEDORA", value:"2008-3379");

  script_name(english:"Fedora 7 : kde-filesystem-4-14.fc7 / kdebase-runtime-4.0.3-10.fc7.1 / kdebase4-4.0.3-9.fc7 / etc (2008-3379)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Bug #443766 - CVE-2008-1670 kdelibs: Buffer overflow in
    KHTML's image loader

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=443766"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009613.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e2e39ba"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009614.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c788bb89"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009615.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5a5742f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?286baf88"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009617.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7e211e5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5981ba14"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdepimlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC7", reference:"kde-filesystem-4-14.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase-runtime-4.0.3-10.fc7.1")) flag++;
if (rpm_check(release:"FC7", reference:"kdebase4-4.0.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdelibs4-4.0.3-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kdepimlibs-4.0.3-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"qt4-4.3.4-11.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kde-filesystem / kdebase-runtime / kdebase4 / kdelibs4 / kdepimlibs / etc");
}
