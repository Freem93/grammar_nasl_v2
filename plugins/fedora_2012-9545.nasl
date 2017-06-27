#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-9545.
#

include("compat.inc");

if (description)
{
  script_id(59548);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/20 23:02:22 $");

  script_xref(name:"FEDORA", value:"2012-9545");

  script_name(english:"Fedora 16 : java-1.6.0-openjdk-1.6.0.0-67.1.11.3.fc16 (2012-9545)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fixes S7079902, CVE-2012-1711: Refine CORBA data models
S7110720: Issue with vm config file loadingIssue with vm config file
loading S7143606, CVE-2012-1717: File.createTempFile should be
improved for temporary files created by the platform. S7143614,
CVE-2012-1716: SynthLookAndFeel stability improvement S7143617,
CVE-2012-1713: Improve fontmanager layout lookup operations S7143851,
CVE-2012-1719: Improve IIOP stub and tie generation in RMIC S7143872,
CVE-2012-1718: Improve certificate extension processing S7145239:
Finetune package definition restriction S7152811, CVE-2012-1723:
Issues in client compiler S7157609, CVE-2012-1724: Issues with loop
S7160677: missing else in fix for 7152811 S7160757, CVE-2012-1725:
Problem with hotspot/runtime_classfile Bug fixes PR1018: JVM fails due
to SEGV during rendering some Unicode characters (part of 6886358)

  - Updated to IcedTea6 1.10.7

    - Removed patch5

    - Fixed build with GCC 4.7

    - Bug fixes

    - PR732: Use xsltproc for bootstrap xslt in place of
      Xerces/Xalan

    - PR881: Sign tests (wsse.policy.basic) failures with
      OpenJDK6

    - Specify both source and target in
      IT_GET_DTDTYPE_CHECK.

    - PR758: [regression] javah from 6hg/b23 generates
      `jlong' from `private int'

    - Install nss.cfg into j2re-image too.

    - Backports

    - S6792400: Avoid loading of Normalizer resources for
      simple uses

    - S7103224: collision between __LEAF define in
      interfaceSupport.hpp and /usr/include/sys/cdefs.h with
      gcc

    - S7140882: Don't return booleans from methods returning
      pointers

    - Updated to IcedTea6-1.11.2

    - Bug fixes

    - RH789154: javac error messages no longer contain the
      full path to the offending file :

    - PR797: Compiler error message does not display entire
      file name and path

    - PR881: Sign tests (wsse.policy.basic) failures with
      OpenJDK6

    - PR886: 6-1.11.1 fails to build CACAO on ppc

    - Specify both source and target in
      IT_GET_DTDTYPE_CHECK.

    - Install nss.cfg into j2re-image too.

    - PR584: Don't use shared Eden in incremental mode.

    - Backports

    - S6792400: Avoid loading of Normalizer resources for
      simple uses

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-June/082381.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dbdbf47"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"java-1.6.0-openjdk-1.6.0.0-67.1.11.3.fc16")) flag++;


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
