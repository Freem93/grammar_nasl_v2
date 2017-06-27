#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60894);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/30 02:34:43 $");

  script_cve_id("CVE-2010-1322");

  script_name(english:"Scientific Linux Security Update : krb5 on SL6.x i386/x86_64");
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
"An uninitialized pointer use flaw was found in the way the MIT
Kerberos KDC handled TGS (Ticket-granting Server) request messages. A
remote, authenticated attacker could use this flaw to crash the KDC
or, possibly, disclose KDC memory or execute arbitrary code with the
privileges of the KDC (krb5kdc). (CVE-2010-1322)

After installing the updated packages, the krb5kdc daemon will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=2219
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b17dc8fe"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"krb5-devel-1.8.2-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-libs-1.8.2-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-pkinit-openssl-1.8.2-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-1.8.2-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-ldap-1.8.2-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-workstation-1.8.2-3.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
