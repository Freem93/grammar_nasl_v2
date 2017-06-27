#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-7fcc957ba6.
#

include("compat.inc");

if (description)
{
  script_id(89303);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/04 16:00:58 $");

  script_xref(name:"FEDORA", value:"2015-7fcc957ba6");

  script_name(english:"Fedora 22 : mingw-spice-gtk-0.30-1.fc22 / mingw-spice-protocol-0.12.10-1.fc22 / spice-0.12.6-1.fc22 / etc (2015-7fcc957ba6)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update spice-gtk/spice-protocol/spice to new upstream releases. The
spice update fixes CVE-2015-3247, CVE-2015-5260 and CVE-2015-5261.
---- Update to spice- gtk 0.29 ---- Update to release 0.12.7

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3546097"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170588.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7030d9aa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f81f3dda"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a90799fc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/170591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?158f1c66"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-spice-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:spice-protocol");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/01");
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
if (rpm_check(release:"FC22", reference:"mingw-spice-gtk-0.30-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"mingw-spice-protocol-0.12.10-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"spice-0.12.6-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"spice-gtk-0.30-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"spice-protocol-0.12.10-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mingw-spice-gtk / mingw-spice-protocol / spice / spice-gtk / etc");
}
