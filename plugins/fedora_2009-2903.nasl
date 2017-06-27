#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-2903.
#

include("compat.inc");

if (description)
{
  script_id(37136);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733");
  script_xref(name:"FEDORA", value:"2009-2903");

  script_name(english:"Fedora 10 : lcms-1.18-1.fc10 (2009-2903)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Mar 23 2009 kwizart < kwizart at gmail.com > -
    1.18-1

    - Update to 1.18 (final)

    - Remove upstreamed patches

    - Disable autoreconf - patch libtool to prevent rpath
      issue

    - Fri Mar 20 2009 kwizart < kwizart at gmail.com > -
      1.18-0.1.beta2

    - Update to 1.18beta2 fix bug #487508: CVE-2009-0723
      LittleCms integer overflow fix bug #487512:
      CVE-2009-0733 LittleCms lack of upper-bounds check on
      sizes fix bug #487509: CVE-2009-0581 LittleCms memory
      leak

  - Mon Mar 2 2009 kwizart < kwizart at gmail.com > -
    1.17-10

    - Fix circle dependency #452352

    - Wed Feb 25 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1.17-9

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    - Thu Dec 4 2008 kwizart < kwizart at gmail.com > -
      1.17-8

    - Fix autoreconf and missing auxiliary files.

    - Sat Nov 29 2008 Ignacio Vazquez-Abrams
      <ivazqueznet+rpm at gmail.com> - 1.17-7

    - Rebuild for Python 2.6

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=487508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=487509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=487512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e29b8365"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lcms package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lcms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"lcms-1.18-1.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lcms");
}
