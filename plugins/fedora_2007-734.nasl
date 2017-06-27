#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-734.
#

include("compat.inc");

if (description)
{
  script_id(27634);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:04:03 $");

  script_cve_id("CVE-2007-5269");
  script_xref(name:"FEDORA", value:"2007-734");

  script_name(english:"Fedora Core 6 : libpng-1.2.10-10.fc6 (2007-734)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Oct 18 2007 Tom Lane <tgl at redhat.com> 2:1.2.10-10

    - Back-port critical fixes from libpng 1.2.22, primarily
      to fix CVE-2007-5269 Related: #324771

  - Update License tag and some other obsolete bits in
    specfile

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7994fd79"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libpng, libpng-debuginfo and / or libpng-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
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
if (rpm_check(release:"FC6", reference:"libpng-1.2.10-10.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"libpng-debuginfo-1.2.10-10.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"libpng-devel-1.2.10-10.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-debuginfo / libpng-devel");
}
