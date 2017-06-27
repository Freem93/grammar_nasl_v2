#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-12758.
#

include("compat.inc");

if (description)
{
  script_id(48330);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 21:05:31 $");

  script_osvdb_id(75193, 75194);
  script_xref(name:"FEDORA", value:"2010-12758");

  script_name(english:"Fedora 12 : java-1.6.0-openjdk-1.6.0.0-40.b18.fc12 (2010-12758)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"# S6678385, RH551835: Fixes jvm crashes when window is resized. #
Produces the 'expected' behavior for full screen applications, when
running the Metacity window manager. # PR453, OJ100142: Fix policy
evaluation to match the proprietary JDK. # IcedTeaNPPlugin. *
RH524387: javax.net.ssl.SSLKeyException: RSA premaster secret error *
Set context classloader for all threads in an applet's threadgroup *
PR436: Close all applet threads on exit * PR480: NPPlugin with
NoScript extension. * PR488: Question mark changing into underscore in
URL. * RH592553: Fix bug causing 100% CPU usage. * Don't generate a
random pointer from a pthread_t in the debug output. * Add
ForbiddenTargetException for legacy support.

  - Use variadic macro for plugin debug message printing. *
    Don't link the plugin with libxul libraries. * Fix race
    conditions in plugin initialization code that were
    causing hangs. * RH506730: BankID (Norwegian common
    online banking authentication system) applet fails to
    load. * PR491: pass java_{code,codebase,archive}
    parameters to Java. * Adds javawebstart.version property
    and give user permission to read that property. # NetX:
    * Fix security flaw in NetX that allows arbitrary
    unsigned apps to set any java property. * Fix a flaw
    that allows unsigned code to access any file on the
    machine (accessible to the user) and write to it. * Make
    path sanitization consistent; use a blacklisting
    approach. * Make the SingleInstanceServer thread a
    daemon thread. * Handle JNLP files which use native
    libraries but do not indicate it * Allow JNLP
    classloaders to share native libraries * Added encoding
    support # PulseAudio: * Eliminate spurious exception
    throwing. # Zero/Shark: * PR483: Fix miscompilation of
    sun.misc.Unsafe::getByte. * PR324,PR481: Fix Shark VM
    crash. * Fix Zero build on Hitachi SH. # SystemTap
    support: * PR476: Enable building SystemTap support on
    GCC 4.5.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/045468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ffac2d2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"java-1.6.0-openjdk-1.6.0.0-40.b18.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk");
}
