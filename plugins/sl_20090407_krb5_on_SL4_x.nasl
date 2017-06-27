#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60564);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846");

  script_name(english:"Scientific Linux Security Update : krb5 on SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An input validation flaw was found in the ASN.1 (Abstract Syntax
Notation One) decoder used by MIT Kerberos. A remote attacker could
use this flaw to crash a network service using the MIT Kerberos
library, such as kadmind or krb5kdc, by causing it to dereference or
free an uninitialized pointer. (CVE-2009-0846)

Multiple input validation flaws were found in the MIT Kerberos GSS-API
library's implementation of the SPNEGO mechanism. A remote attacker
could use these flaws to crash any network service utilizing the MIT
Kerberos GSS-API library to authenticate users or, possibly, leak
portions of the service's memory. (CVE-2009-0844, CVE-2009-0845)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0904&L=scientific-linux-errata&T=0&P=1067
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5ce78b9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"krb5-devel-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-libs-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-server-1.3.4-60.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"krb5-workstation-1.3.4-60.el4_7.2")) flag++;

if (rpm_check(release:"SL5", reference:"krb5-devel-1.6.1-31.el5_3.3")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-libs-1.6.1-31.el5_3.3")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-1.6.1-31.el5_3.3")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-workstation-1.6.1-31.el5_3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
