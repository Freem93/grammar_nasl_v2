#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:169. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(62794);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id("CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5089");
  script_bugtraq_id(55501, 56039, 56058, 56059, 56061, 56063, 56065, 56067, 56071, 56075, 56076, 56080, 56081, 56083);
  script_xref(name:"MDVSA", value:"2012:169");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2012:169)");
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

  - S6631398, CVE-2012-3216: FilePermission improved path
    checking

    - S7093490: adjust package access in rmiregistry

    - S7143535, CVE-2012-5068: ScriptEngine corrected
      permissions

    - S7167656, CVE-2012-5077: Multiple Seeders are being
      created

    - S7169884, CVE-2012-5073: LogManager checks do not work
      correctly for sub-types

  - S7169888, CVE-2012-5075: Narrowing resource definitions
    in JMX RMI connector

  - S7172522, CVE-2012-5072: Improve DomainCombiner checking

    - S7186286, CVE-2012-5081: TLS implementation to better
      adhere to RFC

    - S7189103, CVE-2012-5069: Executors needs to maintain
      state

    - S7189490: More improvements to DomainCombiner checking

    - S7189567, CVE-2012-5085: java net obselete protocol

    - S7192975, CVE-2012-5071: Conditional usage check is
      wrong

    - S7195194, CVE-2012-5084: Better data validation for
      Swing

    - S7195917, CVE-2012-5086: XMLDecoder parsing at
      close-time should be improved

  - S7195919, CVE-2012-5979: (sl) ServiceLoader can throw
    CCE without needing to create instance

  - S7198296, CVE-2012-5089: Refactor classloader usage

    - S7158800: Improve storage of symbol tables

    - S7158801: Improve VM CompileOnly option

    - S7158804: Improve config file parsing

    - S7176337: Additional changes needed for 7158801 fix

    - S7198606, CVE-2012-4416: Improve VM optimization

The updated packages provides icedtea6-1.11.5 which is not vulnerable
to these issues."
  );
  # http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2012-October/020556.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ee15afe"
  );
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0eb44d4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-1.6.0.0-35.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-demo-1.6.0.0-35.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-devel-1.6.0.0-35.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-35.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-src-1.6.0.0-35.b24.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
