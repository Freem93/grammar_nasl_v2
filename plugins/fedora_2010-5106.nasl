#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-5106.
#

include("compat.inc");

if (description)
{
  script_id(47379);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 21:38:17 $");

  script_xref(name:"FEDORA", value:"2010-5106");

  script_name(english:"Fedora 12 : glpi-0.72.4-2.svn11035.fc12 (2010-5106)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version correct several bugs. Full upstream changelog : * Bug
#1893: Unable to access to the model of phones dictionnary * Bug
#1904: Vlan not add using Template * Bug #1906: Message-ID should not
use $SERVER['HTTPHOST'] * Bug #1918: configured listlimitmax not
honnoured * Bug #1941: Disconnecting a port doesn't free the network
point. * Bug #1942: onglet Tous d'un objet * Bug #1946: Business rules
bug on test processing * Bug #1963: expired license for deleted
software * Bug #1969: bandwidth / speed confusion * Bug #1971: Report
by year for software * Bug #2017: Wrong ID for Export ICAL / Webcal *
Bug #2030: Search engine problem : user in lists * Bug #2034:
Interface helpdesk - ticket details - navigation problem * Bug #2035:
Search on warranty date * Bug #2036: Report infocom display improvment
* Bug #2039: OCS manual import do not use link processing * Bug #2042:
Security Problem - root_doc computation * Bug #2043: Security : clean
$SERVER['PHPSELF'] REQUEST_URI... * Bug #2056: LDAP Group retrieval
for external auth * XSS vulnerability in embedded phpCAS

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=575904"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-March/037866.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7067df17"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected glpi package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:glpi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
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
if (rpm_check(release:"FC12", reference:"glpi-0.72.4-2.svn11035.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glpi");
}
