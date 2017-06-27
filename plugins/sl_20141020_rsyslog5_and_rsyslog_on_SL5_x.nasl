#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78647);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/04 14:10:52 $");

  script_cve_id("CVE-2014-3634");

  script_name(english:"Scientific Linux Security Update : rsyslog5 and rsyslog on SL5.x, SL6.x i386/x86_64");
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
"A flaw was found in the way rsyslog handled invalid log message
priority values. In certain configurations, a local attacker, or a
remote attacker able to connect to the rsyslog port, could use this
flaw to crash the rsyslog daemon. (CVE-2014-3634)

After installing the update, the rsyslog service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=2253
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca364eea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"rsyslog5-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"rsyslog5-debuginfo-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"rsyslog5-gnutls-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"rsyslog5-gssapi-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"rsyslog5-mysql-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"rsyslog5-pgsql-5.8.12-5.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"rsyslog5-snmp-5.8.12-5.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"rsyslog-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-debuginfo-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-gnutls-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-gssapi-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-mysql-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-pgsql-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-relp-5.8.10-9.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-snmp-5.8.10-9.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
