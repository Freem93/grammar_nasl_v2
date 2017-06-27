#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-49bf88cd29.
#

include("compat.inc");

if (description)
{
  script_id(89530);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/18 16:52:28 $");

  script_cve_id("CVE-2015-8808");
  script_xref(name:"FEDORA", value:"2016-49bf88cd29");

  script_name(english:"Fedora 22 : GraphicsMagick-1.3.23-1.fc22 / gdl-0.9.5-10.fc22 / octave-3.8.2-19.fc22 / etc (2016-49bf88cd29)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fix for CVE-2015-8808

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1305505"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62077df2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1b71e7c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177836.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ab33b40"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9afa7034"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbe192d8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/177840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?388da7e4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:octave");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:vdr-skinenigmang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:vdr-skinnopacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:vdr-tvguide");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
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
if (rpm_check(release:"FC22", reference:"GraphicsMagick-1.3.23-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"gdl-0.9.5-10.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"octave-3.8.2-19.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"vdr-skinenigmang-0.1.2-27.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"vdr-skinnopacity-1.1.3-9.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"vdr-tvguide-1.2.2-9.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / gdl / octave / vdr-skinenigmang / vdr-skinnopacity / etc");
}
