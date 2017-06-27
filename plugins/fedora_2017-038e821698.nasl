#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-038e821698.
#

include("compat.inc");

if (description)
{
  script_id(97645);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/10 16:46:29 $");

  script_xref(name:"FEDORA", value:"2017-038e821698");

  script_name(english:"Fedora 25 : knot / knot-resolver (2017-038e821698)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Knot Resolver 1.2.3 (2017-02-23) ================================

Bugfixes

--------

  - Disable storing GLUE records into the cache even in the
    (non-default) QUERY_PERMISSIVE mode

  - iterate: skip answer RRs that don't match the query

  - layer/iterate: some additional processing for referrals

  - lib/resolve: zonecut fetching error was fixed

Knot Resolver 1.2.2 (2017-02-10) ================================

Bugfixes :

---------

  - Fix -k argument processing to avoid out-of-bounds memory
    accesses

  - lib/resolve: fix zonecut fetching for explicit DS
    queries

  - hints: more NULL checks

  - Fix TA bootstrapping for multiple TAs in the IANA XML
    file

Testing :

--------

  - Update tests to run tests with and without QNAME
    minimization

Knot Resolver 1.2.1 (2017-02-01) ====================================

Security :

---------

  - Under certain conditions, a cached negative answer from
    a CD query would be reused to construct response for
    non-CD queries, resulting in Insecure status instead of
    Bogus. Only 1.2.0 release was affected.

Documentation

-------------

  - Update the typo in the documentation: The query trace
    policy is named policy.QTRACE (and not policy.TRACE)

Bugfixes :

---------

  - lua: make the map command check its arguments

Knot DNS 2.4.1 (2017-02-10) ===========================

Bugfixes :

--------

  - Transfer of a huge rrset goes into an infinite loop

  - Huge response over TCP contains useless TC bit instead
    of SERVFAIL

  - Failed to build utilities with disabled daemon

  - Memory leaks during keys removal

  - Rough TSIG packet reservation causes early truncation

  - Minor out-of-bounds string termination write in rrset
    dump

  - Server crash during stop if failed to open timers DB

  - Poor minimum UDP-max-size configuration check

  - Failed to receive one-record-per-message IXFR-style AXFR

  - Kdig timeouts when receiving RCODE != NOERROR on
    subsequent transfer message

Improvements :

-------------

  - Speed-up of rdata addition into a huge rrset

  - Introduce check of minumum timeout for next refresh

  - Dnsproxy module can forward all queries without local
    resolving

----

Latest upstream release. Includes bugfixes for DNSSEC key management.

----

Latest upstream versions with bunch of impotant bugfixes.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-038e821698"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected knot and / or knot-resolver packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knot-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"knot-2.4.1-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"knot-resolver-1.2.3-1.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "knot / knot-resolver");
}
