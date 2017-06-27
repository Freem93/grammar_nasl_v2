#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(66891);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/14 10:49:53 $");

  script_cve_id("CVE-2002-2443");

  script_name(english:"Scientific Linux Security Update : krb5 on SL5.x, SL6.x i386/x86_64");
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
"It was found that kadmind's kpasswd service did not perform any
validation on incoming network packets, causing it to reply to all
requests. A remote attacker could use this flaw to send spoofed
packets to a kpasswd service that appear to come from kadmind on a
different server, causing the services to keep replying packets to
each other, consuming network bandwidth and CPU. (CVE-2002-2443)

After installing the updated packages, the krb5kdc and kadmind daemons
will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1306&L=scientific-linux-errata&T=0&P=1086
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8f25d32"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"krb5-debuginfo-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-devel-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-libs-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-ldap-1.6.1-70.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-workstation-1.6.1-70.el5_9.2")) flag++;

if (rpm_check(release:"SL6", reference:"krb5-debuginfo-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-devel-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-libs-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-pkinit-openssl-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-ldap-1.10.3-10.el6_4.3")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-workstation-1.10.3-10.el6_4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
