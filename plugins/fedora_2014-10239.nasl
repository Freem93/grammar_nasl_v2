#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-10239.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77786);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 22:06:07 $");

  script_xref(name:"FEDORA", value:"2014-10239");

  script_name(english:"Fedora 21 : php-symfony-2.5.4-1.fc21 (2014-10239)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 2.5.4 (2014-09-03)

  - security #11832 CVE-2014-6072 (fabpot)

    - security #11831 CVE-2014-5245 (stof)

    - security #11830 CVE-2014-4931 (aitboudad, Jeremy
      Derusse)

    - security #11829 CVE-2014-6061 (damz, fabpot)

    - security #11828 CVE-2014-5244 (nicolas-grekas,
      larowlan)

    - bug #10197 [FrameworkBundle] PhpExtractor bugfix and
      improvements (mtibben)

    - bug #11772 [Filesystem] Add FTP stream wrapper context
      option to enable overwrite (Damian Sromek)

    - bug #11791 [Process] fix mustRun() in sigchild
      environments (xabbuh)

    - bug #11788 [Yaml] fixed mapping keys containing a
      quoted # (hvt, fabpot)

    - bug #11787 fixed DateComparator if file does not exist
      (avi123)

    - bug #11160 [DoctrineBridge] Abstract Doctrine
      Subscribers with tags (merk)

    - bug #11768 [ClassLoader] Add a __call() method to
      XcacheClassLoader (tstoeckler)

    - bug #11739 [Validator] Pass strict argument into the
      strict email validator (brianfreytag)

    - bug #11749 [TwigBundle] Remove hard dependency of
      RequestContext in AssetsExtension (pgodel)

    - bug #11726 [Filesystem Component] mkdir race condition
      fix #11626 (kcassam)

    - bug #11677 [YAML] resolve variables in inlined YAML
      (xabbuh)

    - bug #11639 [DependencyInjection] Fixed factory service
      not within the ServiceReferenceGraph. (boekkooi)

    - bug #11778 [Validator] Fixed wrong translations for
      Collection constraints (samicemalone)

    - bug #11756 [DependencyInjection] fix @return anno
      created by PhpDumper (jakubkulhan)

    - bug #11711 [DoctrineBridge] Fix empty parameter
      logging in the dbal logger (jakzal)

    - bug #11692 [DomCrawler] check for the correct field
      type (xabbuh)

    - bug #11672 [Routing] fix handling of nullable XML
      attributes (xabbuh)

    - bug #11624 [DomCrawler] fix the axes handling in a bc
      way (xabbuh)

    - bug #11676 [Form] Fixed #11675
      ValueToDuplicatesTransformer accept '0' value (Nek-)

    - bug #11695 [Validators] Fixed failing tests requiring
      ICU 52.1 which are skipped otherwise (webmozart)

    - bug #11584 [FrameworkBundle] Fixed validator factory
      definition when the Validator API is 'auto' for PHP <
      5.3.9 (webmozart)

    - bug #11645 [Form] Fixed ValidatorExtension to work
      with the 2.5 Validation API (webmozart)

    - bug #11529 [WebProfilerBundle] Fixed double height of
      canvas (hason)

    - bug #11666 [DIC] Fixed: anonymous services are always
      private (lyrixx)

    - bug #11641 [WebProfilerBundle ] Fix toolbar vertical
      alignment (blaugueux)

    - bug #11637 fix dependencies on HttpFoundation
      component (xabbuh)

    - bug #11559 [Validator] Convert objects to string in
      comparison validators (webmozart)

    - feature #11510 [HttpFoundation] MongoDbSessionHandler
      supports auto expiry via configurable expiry_field
      (catchamonkey)

    - bug #11408 [HttpFoundation] Update QUERY_STRING when
      overrideGlobals (yguedidi)

    - bug #11625 [FrameworkBundle] resolve parameters before
      the configs are processed in the config:debug command
      (xabbuh)

    - bug #11633 [FrameworkBundle] add missing attribute to
      XSD (xabbuh)

    - bug #11601 [Validator] Allow basic auth in url when
      using UrlValidator. (blaugueux)

    - bug #11609 [Console] fixed style creation when
      providing an unknown tag option (fabpot)

    - bug #10914 [HttpKernel] added an analyze of
      environment parameters for built-in server (mauchede)

    - bug #11598 [Finder] Shell escape and windows support
      (Gordon Franke, gimler)

    - bug #11582 [DoctrineBridge] Changed
      UniqueEntityValidator to use the 2.5 Validation API
      (webmozart)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1138285"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/137913.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9541987"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"php-symfony-2.5.4-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony");
}
