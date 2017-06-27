#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:010. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64563);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480");
  script_bugtraq_id(57686, 57687, 57691, 57692, 57694, 57696, 57702, 57703, 57709, 57710, 57711, 57712, 57713, 57715, 57719, 57727, 57729, 57730);
  script_xref(name:"MDVSA", value:"2013:010");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2013:010)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues were identified and fixed in OpenJDK
(icedtea6) :

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

The updated packages provides icedtea6-1.11.6 which is not vulnerable
to these issues."
  );
  # http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2013-February/021708.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e15a1d25"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-1.6.0.0-35.b24.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-demo-1.6.0.0-35.b24.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-devel-1.6.0.0-35.b24.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-35.b24.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-src-1.6.0.0-35.b24.2-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
