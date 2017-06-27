#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85500);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/08/21 13:26:54 $");

  script_cve_id("CVE-2015-5621");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL6.x, SL7.x i386/x86_64");
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
"It was discovered that the snmp_pdu_parse() function could leave
incompletely parsed varBind variables in the list of variables. A
remote, unauthenticated attacker could use this flaw to crash snmpd
or, potentially, execute arbitrary code on the system with the
privileges of the user running snmpd. (CVE-2015-5621)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=17292
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?423be559"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"net-snmp-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-debuginfo-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-devel-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-libs-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-perl-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-python-5.5-54.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-utils-5.5-54.el6_7.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-agent-libs-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-debuginfo-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-devel-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-gui-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-libs-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-perl-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-python-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-sysvinit-5.7.2-20.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-utils-5.7.2-20.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
