#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61178);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-4313");

  script_name(english:"Scientific Linux Security Update : bind on SL5.x, SL6.x i386/x86_64");
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
"The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was discovered in the way BIND handled certain DNS queries,
which caused it to cache an invalid record. A remote attacker could
use this flaw to send repeated queries for this invalid record,
causing the resolvers to exit unexpectedly due to a failed assertion.
(CVE-2011-4313)

Users of bind are advised to upgrade to these updated packages, which
resolve this issue. After installing the update, the BIND daemon
(named) will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1111&L=scientific-linux-errata&T=0&P=2260
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0194b5e8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/17");
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
if (rpm_check(release:"SL5", reference:"bind-9.3.6-16.P1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.6-16.P1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-debuginfo-9.3.6-16.P1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.6-16.P1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.6-16.P1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.6-16.P1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.6-16.P1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.6-16.P1.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.6-16.P1.el5_7.1")) flag++;

if (rpm_check(release:"SL6", reference:"bind-9.7.3-2.el6_1.P3.3")) flag++;
if (rpm_check(release:"SL6", reference:"bind-chroot-9.7.3-2.el6_1.P3.3")) flag++;
if (rpm_check(release:"SL6", reference:"bind-debuginfo-9.7.3-2.el6_1.P3.3")) flag++;
if (rpm_check(release:"SL6", reference:"bind-devel-9.7.3-2.el6_1.P3.3")) flag++;
if (rpm_check(release:"SL6", reference:"bind-libs-9.7.3-2.el6_1.P3.3")) flag++;
if (rpm_check(release:"SL6", reference:"bind-sdb-9.7.3-2.el6_1.P3.3")) flag++;
if (rpm_check(release:"SL6", reference:"bind-utils-9.7.3-2.el6_1.P3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
