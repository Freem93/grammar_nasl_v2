#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60178);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2007-2028");

  script_name(english:"Scientific Linux Security Update : freeradius on SL3.0.x , SL4.x, SL5.x");
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
"A memory leak flaw was found in the way FreeRADIUS parses certain
authentication requests. A remote attacker could send a specially
crafted authentication request which could cause FreeRADIUS to leak a
small amount of memory. If enough of these requests are sent, the
FreeRADIUS daemon would consume a vast quantity of system memory
leading to a possible denial of service. (CVE-2007-2028)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0705&L=scientific-linux-errata&T=0&P=853
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b4a86d6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"freeradius-1.0.1-2.RHEL3.4")) flag++;

if (rpm_check(release:"SL4", reference:"freeradius-1.0.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"SL4", reference:"freeradius-mysql-1.0.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"SL4", reference:"freeradius-postgresql-1.0.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"SL4", reference:"freeradius-unixODBC-1.0.1-3.RHEL4.5")) flag++;

if (rpm_check(release:"SL5", cpu:"i386", reference:"freeradius-1.1.3-1.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"freeradius-mysql-1.1.3-1.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"freeradius-postgresql-1.1.3-1.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"freeradius-unixODBC-1.1.3-1.2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
