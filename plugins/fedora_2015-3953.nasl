#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-3953.
#

include("compat.inc");

if (description)
{
  script_id(81988);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 23:06:18 $");

  script_xref(name:"FEDORA", value:"2015-3953");

  script_name(english:"Fedora 22 : nx-libs-3.5.0.29-1.fc22 (2015-3953)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 3.5.0.29 :

  - further reduction of code size by Mike Gabriel

    - ~/.x2go/config/keystrokes.cfg,
      /etc/x2go/keystrokes.cfg and
      /etc/nxagent/keystrokes.cfg are now respected thanks
      to Horst Schirmeier

  - security fixes for CVE-2011-2895, CVE-2011-4028,
    CVE-2013-4396, CVE-2013-6462, CVE-2014-0209,
    CVE-2014-0210, CVE-2014-0211, CVE-2014-8092,
    CVE-2014-8097, CVE-2014-8095, CVE-2014-8096,
    CVE-2014-8099, CVE-2014-8100, CVE-2014-8102,
    CVE-2014-8101, CVE-2014-8093, CVE-2014-8098,
    CVE-2015-0255 by Michael DePaulo

  - other (build) bug fixes

Update to 3.5.0.28: o Fix non-working Copy+Paste into some rootless Qt
applications when Xfixes extension is enabled in NX. Thanks to Ulrich
Sibiller! o Adapt X11 launchd socket path for recent Mac OS X
versions. o Fix Xinerama on Debian/Ubuntu installation (only worked on
systems that had dpkg-dev installed) and all RPM based distros. o
Partly make nxcomp aware of nx-libs's four-digit version string.
Thanks to Nito Martinez from TheQVD project!

  - Fix unowned directories

    - Minor cleanup

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/152434.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48f454a5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nx-libs package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nx-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC22", reference:"nx-libs-3.5.0.29-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nx-libs");
}
