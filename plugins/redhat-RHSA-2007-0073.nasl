#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0073. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63839);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2006-4339", "CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745");
  script_osvdb_id(32357, 32358, 32393, 32394, 32931, 32932, 32933, 32934);
  script_xref(name:"RHSA", value:"2007:0073");

  script_name(english:"RHEL 4 : java-1.5.0-ibm (RHSA-2007:0073)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1.5.0-ibm packages that correct several security issues are
available for Red Hat Enterprise Linux 4 Extras.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

IBM's 1.5.0 Java release includes the IBM Java 2 Runtime Environment
and the IBM Java 2 Software Development Kit.

Vulnerabilities were discovered in the Java Runtime Environment. An
untrusted applet could use these vulnerabilities to access data from
other applets. (CVE-2006-6736, CVE-2006-6737)

Serialization flaws were discovered in the Java Runtime Environment.
An untrusted applet or application could use these flaws to elevate
its privileges. (CVE-2006-6745)

Buffer overflow vulnerabilities were discovered in the Java Runtime
Environment. An untrusted applet could use these flaws to elevate its
privileges, possibly reading and writing local files or executing
local applications. (CVE-2006-6731)

Daniel Bleichenbacher discovered an attack on PKCS #1 v1.5 signatures.
Where an RSA key with exponent 3 is used it may be possible for an
attacker to forge a PKCS #1 v1.5 signature that would be incorrectly
verified by implementations that do not check for excess data in the
RSA exponentiation result of the signature. (CVE-2006-4339)

All users of java-ibm-1.5.0 should upgrade to these packages, which
contain IBM's 1.5.0 SR3 Java release which resolves these issues.

Please note that the packages in this erratum are identical to those
we released on January 24th 2007 in advisory RHEA-2007:0027. We have
issued this security update because when we released RHEA-2007:0027 we
were not aware that it contained fixes for security issues. If you
have already updated to those packages you will not need to apply this
update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-6731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-6736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-6737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-6745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www-128.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0073.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-1.5.0.3-1jpp.3.el4")) flag++;
if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-demo-1.5.0.3-1jpp.3.el4")) flag++;
if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-devel-1.5.0.3-1jpp.3.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-javacomm-1.5.0.3-1jpp.3.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.3-1jpp.3.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-jdbc-1.5.0.3-1jpp.3.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.3-1jpp.3.el4")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-plugin-1.5.0.3-1jpp.3.el4")) flag++;
if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-src-1.5.0.3-1jpp.3.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
