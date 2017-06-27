#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-1898.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64478);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/19 21:37:38 $");

  script_bugtraq_id(57686, 57687, 57691, 57692, 57694, 57696, 57702, 57703, 57709, 57710, 57711, 57712, 57713, 57715, 57724, 57727, 57729, 57730);
  script_xref(name:"FEDORA", value:"2013-1898");

  script_name(english:"Fedora 16 : java-1.6.0-openjdk-1.6.0.0-69.1.11.6.fc16 (2013-1898)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Rewritten
    java-1.6.0-openjdk-java-access-bridge-security.patch

    - Updated to icedtea6 1.11.6

    - Security fixes

    - S6563318, CVE-2013-0424: RMI data sanitization

    - S6664509, CVE-2013-0425: Add logging context

    - S6664528, CVE-2013-0426: Find log level matching its
      name or value given at construction time

    - S6776941: CVE-2013-0427: Improve thread pool shutdown

    - S7141694, CVE-2013-0429: Improving CORBA internals

    - S7173145: Improve in-memory representation of
      splashscreens

    - S7186945: Unpack200 improvement

    - S7186946: Refine unpacker resource usage

    - S7186948: Improve Swing data validation

    - S7186952, CVE-2013-0432: Improve clipboard access

    - S7186954: Improve connection performance

    - S7186957: Improve Pack200 data validation

    - S7192392, CVE-2013-0443: Better validation of client
      keys

    - S7192393, CVE-2013-0440: Better Checking of order of
      TLS Messages

    - S7192977, CVE-2013-0442: Issue in toolkit thread

    - S7197546, CVE-2013-0428: (proxy) Reflect about
      creating reflective proxies

    - S7200491: Tighten up JTable layout code

    - S7200500: Launcher better input validation

    - S7201064: Better dialogue checking

    - S7201066, CVE-2013-0441: Change modifiers on unused
      fields

    - S7201068, CVE-2013-0435: Better handling of UI
      elements

    - S7201070: Serialization to conform to protocol

    - S7201071, CVE-2013-0433: InetSocketAddress
      serialization issue

    - S8000210: Improve JarFile code quality

    - S8000537, CVE-2013-0450: Contextualize
      RequiredModelMBean class

    - S8000540, CVE-2013-1475: Improve IIOP type reuse
      management

    - S8000631, CVE-2013-1476: Restrict access to class
      constructor

    - S8001235, CVE-2013-0434: Improve JAXP HTTP handling

    - S8001242: Improve RMI HTTP conformance

    - S8001307: Modify ACC_SUPER behavior

    - S8001972, CVE-2013-1478: Improve image processing

    - S8002325, CVE-2013-1480: Improve management of images

    - Backports

    - S7010849: 5/5 Extraneous javac source/target options
      when building sa-jdi

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/098329.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ff2f4a1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/06");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"java-1.6.0-openjdk-1.6.0.0-69.1.11.6.fc16")) flag++;


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
