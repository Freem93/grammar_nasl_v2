#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:095. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(59561);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/11/18 01:30:18 $");

  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725");
  script_xref(name:"MDVSA", value:"2012:095");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2012:095)");
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

  - S7079902, CVE-2012-1711: Refine CORBA data models

    - S7143617, CVE-2012-1713: Improve fontmanager layout
      lookup operations

    - S7143614, CVE-2012-1716: SynthLookAndFeel stability
      improvement

    - S7143606, CVE-2012-1717: File.createTempFile should be
      improved for temporary files created by the platform.

  - S7143872, CVE-2012-1718: Improve certificate extension
    processing

    - S7143851, CVE-2012-1719: Improve IIOP stub and tie
      generation in RMIC

    - S7152811, CVE-2012-1723: Issues in client compiler

    - S7157609, CVE-2012-1724: Issues with loop

    - S7160757, CVE-2012-1725: Problem with
      hotspot/runtime_classfile

    - S7110720: Issue with vm config file loadingIssue with
      vm config file loading

  - S7145239: Finetune package definition restriction

    - S7160677: missing else in fix for 7152811

The updated packages provides icedtea6-1.11.3 which is not vulnerable
to these issues."
  );
  # http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2012-June/019076.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19419b64"
  );
  # http://www.oracle.com/technetwork/topics/security/javacpujun2012-1515912.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7760536b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-1.6.0.0-26.b24.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-demo-1.6.0.0-26.b24.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-devel-1.6.0.0-26.b24.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-26.b24.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-src-1.6.0.0-26.b24.1mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-1.6.0.0-26.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-demo-1.6.0.0-26.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-devel-1.6.0.0-26.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-26.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-src-1.6.0.0-26.b24.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
