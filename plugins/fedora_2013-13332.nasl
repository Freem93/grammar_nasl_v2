#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-13332.
#

include("compat.inc");

if (description)
{
  script_id(69216);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 21:12:41 $");

  script_cve_id("CVE-2013-1436");
  script_xref(name:"FEDORA", value:"2013-13332");

  script_name(english:"Fedora 19 : bluetile-0.6-18.fc19 / ghc-X11-1.6.1.1-1.fc19 / ghc-X11-xft-0.3.1-10.fc19 / etc (2013-13332)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - xmonad-contrib-0.11.2 fixes a vulnerability in the
    DynamicLog module

    - update X11 to 1.6.1.1

    - update xmobar to 0.18

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=989670"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d5835b2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113314.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19c0a24e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113315.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b819b46"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113316.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf8eeca4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113317.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08c77e80"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113318.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?041c9fbf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bluetile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ghc-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ghc-X11-xft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ghc-xmonad-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xmobar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xmonad");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"bluetile-0.6-18.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ghc-X11-1.6.1.1-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ghc-X11-xft-0.3.1-10.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"ghc-xmonad-contrib-0.11.2-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"xmobar-0.18-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"xmonad-0.11-4.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluetile / ghc-X11 / ghc-X11-xft / ghc-xmonad-contrib / xmobar / etc");
}
