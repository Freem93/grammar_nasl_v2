#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60487);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:07 $");

  script_cve_id("CVE-2008-4309");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"A denial-of-service flaw was found in the way Net-SNMP processes SNMP
GETBULK requests. A remote attacker who issued a specially crafted
request could cause the snmpd server to crash. (CVE-2008-4309)

Note: An attacker must have read access to the SNMP server in order to
exploit this flaw. In the default configuration, the community name
'public' grants read-only access. In production deployments, it is
recommended to change this default community name."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0811&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a98e9321"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"net-snmp-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"SL3", reference:"net-snmp-devel-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"SL3", reference:"net-snmp-libs-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"SL3", reference:"net-snmp-perl-5.0.9-2.30E.25")) flag++;
if (rpm_check(release:"SL3", reference:"net-snmp-utils-5.0.9-2.30E.25")) flag++;

if (rpm_check(release:"SL4", reference:"net-snmp-5.1.2-13.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"net-snmp-devel-5.1.2-13.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"net-snmp-libs-5.1.2-13.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"net-snmp-perl-5.1.2-13.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"net-snmp-utils-5.1.2-13.el4_7.2")) flag++;

if (rpm_check(release:"SL5", reference:"net-snmp-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-devel-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-libs-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-perl-5.3.1-24.el5_2.2")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-utils-5.3.1-24.el5_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
