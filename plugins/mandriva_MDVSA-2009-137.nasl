#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:137. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(39478);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id(
    "CVE-2006-2426",
    "CVE-2009-0581",
    "CVE-2009-0723",
    "CVE-2009-0733",
    "CVE-2009-0793",
    "CVE-2009-0794",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1097",
    "CVE-2009-1098",
    "CVE-2009-1101",
    "CVE-2009-1102"
  );
  script_bugtraq_id(
    34185,
    34240,
    34411
  );
  script_osvdb_id(
    25561,
    53164,
    53165,
    53166,
    53167,
    53168,
    53172,
    53173,
    56307,
    56308,
    56309,
    56310,
    56413
  );
  script_xref(name:"MDVSA", value:"2009:137");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2009:137)");
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
"Multiple security vulnerabilities has been identified and fixed in
Little cms library embedded in OpenJDK :

A memory leak flaw allows remote attackers to cause a denial of
service (memory consumption and application crash) via a crafted image
file (CVE-2009-0581).

Multiple integer overflows allow remote attackers to execute arbitrary
code via a crafted image file that triggers a heap-based buffer
overflow (CVE-2009-0723).

Multiple stack-based buffer overflows allow remote attackers to
execute arbitrary code via a crafted image file associated with a
large integer value for the (1) input or (2) output channel
(CVE-2009-0733).

A flaw in the transformations of monochrome profiles allows remote
attackers to cause denial of service triggered by a NULL pointer
dereference via a crafted image file (CVE-2009-0793).

Further security fixes in the JRE and in the Java API of OpenJDK :

A flaw in handling temporary font files by the Java Virtual Machine
(JVM) allows remote attackers to cause denial of service
(CVE-2006-2426).

An integer overflow flaw was found in Pulse-Java when handling Pulse
audio source data lines. An attacker could use this flaw to cause an
applet to crash, leading to a denial of service (CVE-2009-0794).

A flaw in Java Runtime Environment initialized LDAP connections allows
authenticated remote users to cause denial of service on the LDAP
service (CVE-2009-1093).

A flaw in the Java Runtime Environment LDAP client in handling server
LDAP responses allows remote attackers to execute arbitrary code on
the client side via malicious server response (CVE-2009-1094).

Buffer overflows in the the Java Runtime Environment unpack200 utility
allow remote attackers to execute arbitrary code via an crafted applet
(CVE-2009-1095, CVE-2009-1096).

A buffer overflow in the splash screen processing allows a attackers
to execute arbitrary code (CVE-2009-1097).

A buffer overflow in GIF images handling allows remote attackers to
execute arbitrary code via an crafted GIF image (CVE-2009-1098).

A flaw in the Java API for XML Web Services (JAX-WS) service endpoint
handling allows remote attackers to cause a denial of service on the
service endpoint's server side (CVE-2009-1101).

A flaw in the Java Runtime Environment Virtual Machine code generation
allows remote attackers to execute arbitrary code via a crafted applet
(CVE-2009-1102).

This update provides fixes for these issues.

Update :

java-1.6.0-openjdk requires rhino packages and these has been further
updated."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rhino-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rhino-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rhino-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-1.6.0.0-0.20.b16.0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.20.b16.0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.20.b16.0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.20.b16.0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-0.20.b16.0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-src-1.6.0.0-0.20.b16.0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rhino-1.7-0.0.2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rhino-demo-1.7-0.0.2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rhino-javadoc-1.7-0.0.2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rhino-manual-1.7-0.0.2.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-1.6.0.0-0.20.b16.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.20.b16.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.20.b16.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.20.b16.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-0.20.b16.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-src-1.6.0.0-0.20.b16.0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"rhino-1.7-0.0.3.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"rhino-demo-1.7-0.0.3.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"rhino-javadoc-1.7-0.0.3.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"rhino-manual-1.7-0.0.3.1mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
