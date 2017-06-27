#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-9604.
#

include("compat.inc");

if (description)
{
  script_id(34825);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 22:32:47 $");

  script_cve_id("CVE-2005-0706");
  script_xref(name:"FEDORA", value:"2008-9604");

  script_name(english:"Fedora 9 : grip-3.2.0-24.fc9 (2008-9604)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Sun Nov 9 2008 Adrian Reber <adrian at lisas.de> -
    1:3.2.0-24

    - fixed 'buffer overflow caused by large amount of CDDB
      replies' (#470552) (CVE-2005-0706)

  - Thu Oct 2 2008 Adrian Reber <adrian at lisas.de> -
    1:3.2.0-23

    - fixed 'German Umlauts are shown incorrectly' (#459394)
      (not converting de.po and fr.po to UTF-8 anymore)

  - Sat Aug 23 2008 Adrian Reber <adrian at lisas.de> -
    1:3.2.0-22

    - updated to better 'execute command after encode' patch
      from Stefan Becker

    - Sun Aug 10 2008 Adrian Reber <adrian at lisas.de> -
      1:3.2.0-21

    - added 'execute command after encode' patch (#457186)

    - Sat Jul 26 2008 Adrian Reber <adrian at lisas.de> -
      1:3.2.0-20

    - fixed 'Grip silently crahses on F8' (#456721)
      (converted non UTF-8 .po files to UTF-8)

  - Tue Jun 10 2008 Adrian Reber <adrian at lisas.de> -
    1:3.2.0-19

    - removed now unnecessary cell-renderer patch

    - fixed 'default config creates ogg files with .mp3
      extension' (#427017)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470552"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016296.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55c02913"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected grip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:grip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/21");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"grip-3.2.0-24.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grip");
}
