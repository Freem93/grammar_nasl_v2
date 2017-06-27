#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(77700);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/16 10:47:19 $");

  script_cve_id("CVE-2014-3596");

  script_name(english:"Scientific Linux Security Update : axis on SL5.x, SL6.x i386/x86_64");
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
"It was discovered that Axis incorrectly extracted the host name from
an X.509 certificate subject's Common Name (CN) field. A
man-in-the-middle attacker could use this flaw to spoof an SSL server
using a specially crafted X.509 certificate. (CVE-2014-3596)

Applications using Apache Axis must be restarted for this update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1409&L=scientific-linux-errata&T=0&P=1366
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a91b707"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");
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
if (rpm_check(release:"SL5", reference:"axis-1.2.1-2jpp.8.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"axis-debuginfo-1.2.1-2jpp.8.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"axis-javadoc-1.2.1-2jpp.8.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"axis-manual-1.2.1-2jpp.8.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"axis-1.2.1-7.5.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"axis-javadoc-1.2.1-7.5.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"axis-manual-1.2.1-7.5.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
