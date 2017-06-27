#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:126. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(55853);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/07/01 13:30:48 $");

  script_cve_id("CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871");
  script_bugtraq_id(48137, 48139, 48140, 48142, 48144, 48146, 48147);
  script_xref(name:"MDVSA", value:"2011:126");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2011:126)");
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
"Multiple vulnerabilities were discovered and corrected in
java-1.6.0-openjdk :

Unspecified vulnerability in the Java Runtime Environment (JRE)
component in Oracle Java SE 6 Update 25 and earlier, 5.0 Update 29 and
earlier, and 1.4.2_31 and earlier allows remote untrusted Java Web
Start applications and untrusted Java applets to affect integrity via
unknown vectors related to Deserialization (CVE-2011-0865).

Multiple unspecified vulnerabilities in the Java Runtime Environment
(JRE) component in Oracle Java SE 6 Update 25 and earlier, 5.0 Update
29 and earlier, and 1.4.2_31 and earlier allow remote attackers to
affect confidentiality, integrity, and availability via unknown
vectors related to 2D (CVE-2011-0862).

Unspecified vulnerability in the Java Runtime Environment (JRE)
component in Oracle Java SE 6 Update 25 and earlier, 5.0 Update 29 and
earlier, and 1.4.2_31 and earlier allows remote untrusted Java Web
Start applications and untrusted Java applets to affect
confidentiality via unknown vectors related to Networking
(CVE-2011-0867).

Unspecified vulnerability in the Java Runtime Environment (JRE)
component in Oracle Java SE 6 Update 26 and earlier allows remote
untrusted Java Web Start applications and untrusted Java applets to
affect confidentiality via unknown vectors related to SAAJ
(CVE-2011-0869).

Unspecified vulnerability in the Java Runtime Environment (JRE)
component in Oracle Java SE 6 Update 25 and earlier allows remote
attackers to affect confidentiality via unknown vectors related to 2D
(CVE-2011-0868).

Unspecified vulnerability in the Java Runtime Environment (JRE)
component in Oracle Java SE 6 Update 25 and earlier, 5.0 Update 29 and
earlier, and 1.4.2_31 and earlier allows remote untrusted Java Web
Start applications and untrusted Java applets to affect
confidentiality, integrity, and availability via unknown vectors
related to HotSpot (CVE-2011-0864).

Unspecified vulnerability in the Java Runtime Environment (JRE)
component in Oracle Java SE 6 Update 25 and earlier, 5.0 Update 29 and
earlier, and 1.4.2_31 and earlier allows remote untrusted Java Web
Start applications and untrusted Java applets to affect
confidentiality, integrity, and availability via unknown vectors
related to Swing (CVE-2011-0871).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been upgraded to versions which is not
vulnerable to these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xrender-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xrender1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxrender-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxrender1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"icedtea-web-1.0.4-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-1.6.0.0-22.b22.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-demo-1.6.0.0-22.b22.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-devel-1.6.0.0-22.b22.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-22.b22.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-src-1.6.0.0-22.b22.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64xrender-devel-0.9.6-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64xrender-static-devel-0.9.6-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64xrender1-0.9.6-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libxrender-devel-0.9.6-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libxrender-static-devel-0.9.6-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libxrender1-0.9.6-0.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"icedtea-web-1.0.4-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-1.6.0.0-22.b22.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-demo-1.6.0.0-22.b22.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-devel-1.6.0.0-22.b22.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-22.b22.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-src-1.6.0.0-22.b22.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xrender-devel-0.9.6-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xrender-static-devel-0.9.6-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64xrender1-0.9.6-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxrender-devel-0.9.6-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxrender-static-devel-0.9.6-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libxrender1-0.9.6-0.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
