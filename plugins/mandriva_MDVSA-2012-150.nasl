#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:150. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(62444);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/10/25 10:43:06 $");

  script_cve_id("CVE-2012-0547", "CVE-2012-1682");
  script_bugtraq_id(55336, 55339);
  script_xref(name:"MDVSA", value:"2012:150-1");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2012:150-1)");
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

Unspecified vulnerability in the Java Runtime Environment (JRE)
component in Oracle Java SE 7 Update 6 and earlier, and 6 Update 34
and earlier, has no impact and remote attack vectors involving AWT and
a security-in-depth issue that is not directly exploitable but which
can be used to aggravate security vulnerabilities that can be directly
exploited. NOTE: this identifier was assigned by the Oracle CNA, but
CVE is not intended to cover defense-in-depth issues that are only
exposed by the presence of other vulnerabilities (CVE-2012-0547).

Unspecified vulnerability in the Java Runtime Environment (JRE)
component in Oracle Java SE 7 Update 6 and earlier allows remote
attackers to affect confidentiality, integrity, and availability via
unknown vectors related to Beans, a different vulnerability than
CVE-2012-3136 (CVE-2012-1682).

The updated packages provides icedtea6-1.11.4 which is not vulnerable
to these issues."
  );
  # http://www.oracle.com/technetwork/topics/security/alert-CVE-2012-4681-1835715.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d17abaf"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/06");
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
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-1.6.0.0-34.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-demo-1.6.0.0-34.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-devel-1.6.0.0-34.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-34.b24.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-src-1.6.0.0-34.b24.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
