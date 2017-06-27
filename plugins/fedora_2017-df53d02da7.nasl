#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-df53d02da7.
#

include("compat.inc");

if (description)
{
  script_id(97842);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/21 13:39:52 $");

  script_xref(name:"FEDORA", value:"2017-df53d02da7");

  script_name(english:"Fedora 25 : knot-resolver (2017-df53d02da7)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"new upstream release

  + security: Knot Resolver 1.2.0 and higher could return AD
    flag for insecure answer if the daemon received answer
    with invalid RRSIG several times in a row.

  + fix: layer/iterate: some improvements in cname chain
    unrolling

  + fix: layer/validate: fix duplicate records in AUTHORITY
    section in case

  + fix: of WC expansion proof

  + fix: lua: do *not* truncate cache size to unsigned

  + fix: forwarding mode: correctly forward +cd flag

  + fix: fix a potential memory leak

  + fix: don't treat answers that contain DS non-existance
    proof as insecure

  + fix: don't store NSEC3 and their signatures in the cache

  + fix: layer/iterate: when processing delegations, check
    if qname is at or below new authority

  + enhancement: modules/policy: allow QTRACE policy to be
    chained with other policies

  + enhancement: hints.add_hosts(path): a new property

  + enhancement: module: document the API and simplify the
    code

  + enhancement: policy.MIRROR: support IPv6 link-local
    addresses

  + enhancement: policy.FORWARD: support IPv6 link-local
    addresses

  + enhancement: add net.outgoing_{v4,v6} to allow
    specifying address to use for connections

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-df53d02da7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected knot-resolver package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knot-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/21");
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
if (rpm_check(release:"FC25", reference:"knot-resolver-1.2.4-1.fc25")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "knot-resolver");
}
