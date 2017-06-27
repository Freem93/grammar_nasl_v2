#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-815.
#

include("compat.inc");

if (description)
{
  script_id(19721);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 21:38:05 $");

  script_xref(name:"FEDORA", value:"2005-815");

  script_name(english:"Fedora Core 3 : lesstif-0.93.36-6.FC3.2 (2005-815)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri May 6 2005 Thomas Woerner <twoerner at redhat.com>
    0.93-36-6.FC3.2

    - fixed possible libXpm overflows (#151640)

    - allow to write XPM files with absolute path names
      again (#140815)

  - Fri Nov 26 2004 Thomas Woerner <twoerner at redhat.com>
    0.93.36-6.FC3.1

    - fixed CVE-2004-0687 (integer overflows) and
      CVE-2004-0688 (stack overflows) in embedded Xpm
      library (#135080)

  - latest Xpm patches: CVE-2004-0914 (#135081)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-August/001305.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3faddfb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected lesstif, lesstif-debuginfo and / or lesstif-devel
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lesstif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lesstif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lesstif-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"lesstif-0.93.36-6.FC3.2")) flag++;
if (rpm_check(release:"FC3", reference:"lesstif-debuginfo-0.93.36-6.FC3.2")) flag++;
if (rpm_check(release:"FC3", reference:"lesstif-devel-0.93.36-6.FC3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lesstif / lesstif-debuginfo / lesstif-devel");
}
