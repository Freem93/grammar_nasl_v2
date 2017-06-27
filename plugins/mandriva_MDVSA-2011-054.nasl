#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:054. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(53001);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id("CVE-2010-4351", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4476", "CVE-2011-0025", "CVE-2011-0706");
  script_bugtraq_id(45894, 46091, 46110, 46387, 46397, 46398, 46399, 46400, 46404, 46406, 46439);
  script_xref(name:"MDVSA", value:"2011:054");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2011:054)");
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
"Multiple vulnerabilities has been identified and fixed in
java-1.6.0-openjdk :

The JNLP SecurityManager in IcedTea (IcedTea.so) 1.7 before 1.7.7, 1.8
before 1.8.4, and 1.9 before 1.9.4 for Java OpenJDK returns from the
checkPermission method instead of throwing an exception in certain
circumstances, which might allow context-dependent attackers to bypass
the intended security policy by creating instances of ClassLoader
(CVE-2010-4351).

Unspecified vulnerability in the Java Runtime Environment (JRE) in
Oracle Java SE and Java for Business 6 Update 23 and earlier, 5.0
Update 27 and earlier, and 1.4.2_29 earlier allows remote untrusted
Java Web Start applications and untrusted Java applets to affect
integrity via unknown vectors related to Networking. NOTE: the
previous information was obtained from the February 2011 CPU. Oracle
has not commented on claims from a downstream vendor that this issue
involves DNS cache poisoning by untrusted applets. (CVE-2010-4448)

Unspecified vulnerability in the Java Runtime Environment (JRE) in
Oracle Java SE and Java for Business 6 Update 23 and earlier for
Solaris and Linux; 5.0 Update 27 and earlier for Solaris and Linux;
and 1.4.2_29 and earlier for Solaris and Linux allows local standalone
applications to affect confidentiality, integrity, and availability
via unknown vectors related to Launcher. NOTE: the previous
information was obtained from the February 2011 CPU. Oracle has not
commented on claims from a downstream vendor that this issue is an
untrusted search path vulnerability involving an empty LD_LIBRARY_PATH
environment variable (CVE-2010-4450).

Unspecified vulnerability in the Java Runtime Environment (JRE) in
Oracle Java SE and Java for Business 6 Update 23 and earlier, 5.0
Update 27 and earlier, and 1.4.2_29 and earlier allows remote
untrusted Java Web Start applications and untrusted Java applets to
affect confidentiality, integrity, and availability via unknown
vectors related to Swing. NOTE: the previous information was obtained
from the February 2011 CPU. Oracle has not commented on claims from a
downstream vendor that this issue is related to the lack of framework
support by AWT event dispatch, and/or clipboard access in Applets.
(CVE-2010-4465)

Unspecified vulnerability in the Java Runtime Environment (JRE) in
Oracle Java SE and Java for Business 6 Update 23 and earlier, 5.0
Update 27 and earlier, and 1.4.2_29 and earlier allows remote
untrusted Java Web Start applications and untrusted Java applets to
affect confidentiality, integrity, and availability via unknown
vectors related to HotSpot. NOTE: the previous information was
obtained from the February 2011 CPU. Oracle has not commented on
claims from a downstream vendor that this issue is heap corruption
related to the Verifier and backward jsrs. (CVE-2010-4469)

Unspecified vulnerability in the Java Runtime Environment (JRE) in
Oracle Java SE and Java for Business 6 Update 23, and, and earlier
allows remote attackers to affect availability via unknown vectors
related to JAXP and unspecified APIs. NOTE: the previous information
was obtained from the February 2011 CPU. Oracle has not commented on
claims from a downstream vendor that this issue is related to Features
set on SchemaFactory not inherited by Validator. (CVE-2010-4470)

Unspecified vulnerability in the Java Runtime Environment (JRE) in
Oracle Java SE and Java for Business 6 Update 23 and earlier, and 5.0
Update 27 and earlier allows remote untrusted Java Web Start
applications and untrusted Java applets to affect confidentiality via
unknown vectors related to 2D. NOTE: the previous information was
obtained from the February 2011 CPU. Oracle has not commented on
claims from a downstream vendor that this issue is related to the
exposure of system properties via vectors related to Font.createFont
and exception text (CVE-2010-4471).

Unspecified vulnerability in the Java Runtime Environment (JRE) in
Oracle Java SE and Java for Business 6 Update 23 and earlier allows
remote attackers to affect availability, related to XML Digital
Signature and unspecified APIs. NOTE: the previous information was
obtained from the February 2011 CPU. Oracle has not commented on
claims from a downstream vendor that this issue involves the
replacement of the XML DSig Transform or C14N algorithm
implementations. (CVE-2010-4472)

The Double.parseDouble method in Java Runtime Environment (JRE) in
Oracle Java SE and Java for Business 6 Update 23 and earlier, 5.0
Update 27 and earlier, and 1.4.2_29 and earlier, as used in OpenJDK,
Apache, JBossweb, and other products, allows remote attackers to cause
a denial of service via a crafted string that triggers an infinite
loop of estimations during conversion to a double-precision binary
floating-point number, as demonstrated using 2.2250738585072012e-308
(CVE-2010-4476).

IcedTea 1.7 before 1.7.8, 1.8 before 1.8.5, and 1.9 before 1.9.5 does
not properly verify signatures for JAR files that (1) are partially
signed or (2) signed by multiple entities, which allows remote
attackers to trick users into executing code that appears to come from
a trusted source (CVE-2011-0025).

The JNLPClassLoader class in IcedTea-Web before 1.0.1, as used in
OpenJDK Runtime Environment 1.6.0, allows remote attackers to gain
privileges via unknown vectors related to multiple signers and the
assignment of an inappropriate security descriptor. (CVE-2011-0706)

Additionally the java-1.5.0-gcj packages were not rebuilt with the
shipped version on GCC for 2009.0 and Enterprise Server 5 which caused
problems while building the java-1.6.0-openjdk updates, therefore
rebuilt java-1.5.0-gcj packages are being provided with this advisory
as well.

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.5.0-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.5.0-gcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.5.0-gcj-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.5.0-gcj-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"java-1.5.0-gcj-1.5.0.0-17.1.7.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.5.0-gcj-devel-1.5.0.0-17.1.7.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.5.0-gcj-javadoc-1.5.0.0-17.1.7.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.5.0-gcj-src-1.5.0.0-17.1.7.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-1.6.0.0-7.b18.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-demo-1.6.0.0-7.b18.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-devel-1.6.0.0-7.b18.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-7.b18.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-7.b18.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-src-1.6.0.0-7.b18.5mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-1.6.0.0-7.b18.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-demo-1.6.0.0-7.b18.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-devel-1.6.0.0-7.b18.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-7.b18.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-7.b18.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"java-1.6.0-openjdk-src-1.6.0.0-7.b18.5mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-1.6.0.0-7.b18.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-demo-1.6.0.0-7.b18.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-devel-1.6.0.0-7.b18.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-7.b18.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-7.b18.5mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-src-1.6.0.0-7.b18.5mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
