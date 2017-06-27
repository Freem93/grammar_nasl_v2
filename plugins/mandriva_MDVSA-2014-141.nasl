#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:141. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(76887);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/28 19:00:56 $");

  script_cve_id("CVE-2014-2483", "CVE-2014-2490", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4221", "CVE-2014-4223", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4266");
  script_bugtraq_id(68562, 68571, 68583, 68590, 68596, 68599, 68608, 68620, 68624, 68636, 68639, 68642, 68645);
  script_xref(name:"MDVSA", value:"2014:141");

  script_name(english:"Mandriva Linux Security Advisory : java-1.7.0-openjdk (MDVSA-2014:141)");
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
"Updated java-1.7.0-openjdk packages fix security vulnerabilities :

It was discovered that the Hotspot component in OpenJDK did not
properly verify bytecode from the class files. An untrusted Java
application or applet could possibly use these flaws to bypass Java
sandbox restrictions (CVE-2014-4216, CVE-2014-4219).

A format string flaw was discovered in the Hotspot component event
logger in OpenJDK. An untrusted Java application or applet could use
this flaw to crash the Java Virtual Machine or, potentially, execute
arbitrary code with the privileges of the Java Virtual Machine
(CVE-2014-2490).

Multiple improper permission check issues were discovered in the
Libraries component in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions
(CVE-2014-4223, CVE-2014-4262, CVE-2014-2483).

Multiple flaws were discovered in the JMX, Libraries, Security, and
Serviceability components in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass certain Java sandbox
restrictions (CVE-2014-4209, CVE-2014-4218, CVE-2014-4221,
CVE-2014-4252, CVE-2014-4266).

It was discovered that the RSA algorithm in the Security component in
OpenJDK did not sufficiently perform blinding while performing
operations that were using private keys. An attacker able to measure
timing differences of those operations could possibly leak information
about the used keys (CVE-2014-4244).

The Diffie-Hellman (DH) key exchange algorithm implementation in the
Security component in OpenJDK failed to validate public DH parameters
properly. This could cause OpenJDK to accept and use weak parameters,
allowing an attacker to recover the negotiated key (CVE-2014-4263).

This update is based on IcedTea version 2.5.1, which fixes these
issues, as well as several others."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0292.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.65-2.5.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.65-2.5.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.65-2.5.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.65-2.5.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.65-2.5.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"java-1.7.0-openjdk-javadoc-1.7.0.65-2.5.1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.65-2.5.1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
