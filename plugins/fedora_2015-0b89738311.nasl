#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-0b89738311.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(89139);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_cve_id("CVE-2015-8124", "CVE-2015-8125");
  script_xref(name:"FEDORA", value:"2015-0b89738311");

  script_name(english:"Fedora 22 : php-symfony-2.7.7-2.fc22 / php-twig-1.23.1-2.fc22 (2015-0b89738311)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Twig 1.23.1** (2015-11-05) * fixed some exception messages which
triggered PHP warnings * fixed BC on Twig_Test_NodeTestCase **Twig
1.23.0** (2015-10-29)

  - deprecated the possibility to override an extension by
    registering another one with the same name * deprecated
    Twig_ExtensionInterface::getGlobals() (added
    Twig_Extension_GlobalsInterface for BC) * deprecated
    Twig_ExtensionInterface::initRuntime() (added
    Twig_Extension_InitRuntimeInterface for BC) * deprecated
    Twig_Environment::computeAlternatives() **Symfony
    2.7.7** (2015-11-23) * security #16631 CVE-2015-8124:
    Session Fixation in the 'Remember Me' Login Feature
    (xabbuh) * security #16630 CVE-2015-8125: Potential
    Remote Timing Attack Vulnerability in Security
    Remember-Me Service (xabbuh) * bug #16588 Sent out a
    status text for unknown HTTP headers. (dawehner) * bug
    #16295 [DependencyInjection] Unescape parameters for all
    types of injection (Nicofuma)

  - bug #16574 [Process] Fix PhpProcess with phpdbg runtime
    (nicolas-grekas) * bug #16578 [Console] Fix bug in
    windows detection (kbond) * bug #16546 [Serializer]
    ObjectNormalizer: don't serialize static methods and
    props (dunglas) * bug #16352 Fix the server variables in
    the router_*.php files (leofeyer) * bug #16537
    [Validator] Allow an empty path with a non empty
    fragment or a query (jakzal) * bug #16528 [Translation]
    Add support for Armenian pluralization. (marcosdsanchez)
    * bug #16510 [Process] fix Proccess run with pts enabled
    (ewgRa) * bug #16292 fix race condition at mkdir
    (#16258) (ewgRa) * bug #15945 [Form] trigger deprecation
    warning when using empty_value (xabbuh) * bug #16384
    [FrameworkBundle] JsonDescriptor - encode container
    params only once (xabbuh) * bug #16480 [VarDumper] Fix
    PHP7 type- hints compat (nicolas-grekas) * bug #16463
    [PropertyAccess] Port of the performance optimization
    from 2.3 (dunglas) * bug #16462 [PropertyAccess] Fix
    dynamic property accessing. (dunglas) * bug #16454
    [Serializer] GetSetNormalizer shouldn't set/get static
    methods (boekkooi) * bug #16453 [Serializer]
    PropertyNormalizer shouldn't set static properties
    (boekkooi) * bug #16471 [VarDumper] Fix casting for
    ReflectionParameter (nicolas-grekas) * bug #16294
    [PropertyAccess] Major performance improvement (dunglas)
    * bug #16331 fixed Twig deprecation notices (fabpot) *
    bug #16306 [DoctrineBridge] Fix issue which prevent the
    profiler to explain a query (Baachi) * bug #16359 Use
    mb_detect_encoding with $strict = true (nicolas-grekas)
    * bug #16144 [Security] don't allow to install the split
    Security packages (xabbuh)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1285263"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/173300.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcac22c8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/173301.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abef81ff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony and / or php-twig packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-twig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/05");
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
if (rpm_check(release:"FC22", reference:"php-symfony-2.7.7-2.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"php-twig-1.23.1-2.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony / php-twig");
}
