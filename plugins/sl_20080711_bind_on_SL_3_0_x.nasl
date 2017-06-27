#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60437);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/29 04:36:30 $");

  script_cve_id("CVE-2008-1447");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"Scientific Linux Security Update : bind on SL 3.0.x , SL 4.x, SL 5.x");
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
"The DNS protocol protects against spoofing attacks by requiring an
attacker to predict both the DNS transaction ID and UDP source port of
a request. In recent years, a number of papers have found problems
with DNS implementations which make it easier for an attacker to
perform DNS cache-poisoning attacks.

Previous versions of BIND did not use randomized UDP source ports. If
an attacker was able to predict the random DNS transaction ID, this
could make DNS cache-poisoning attacks easier. In order to provide
more resilience, BIND has been updated to use a range of random UDP
source ports. (CVE-2008-1447)

Note: This errata also updates SELinux policy to allow BIND to use
random UDP source ports."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=432
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd651c8f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", cpu:"x86_64", reference:"bind-9.2.4-22.el3")) flag++;
if (rpm_check(release:"SL3", cpu:"x86_64", reference:"bind-chroot-9.2.4-22.el3")) flag++;
if (rpm_check(release:"SL3", cpu:"x86_64", reference:"bind-devel-9.2.4-22.el3")) flag++;
if (rpm_check(release:"SL3", cpu:"x86_64", reference:"bind-libs-9.2.4-22.el3")) flag++;
if (rpm_check(release:"SL3", cpu:"x86_64", reference:"bind-utils-9.2.4-22.el3")) flag++;

if (rpm_check(release:"SL4", reference:"bind-9.2.4-28.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"bind-chroot-9.2.4-28.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"bind-devel-9.2.4-28.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"bind-libs-9.2.4-28.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"bind-utils-9.2.4-28.0.1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"selinux-policy-targeted-1.17.30-2.150.el4")) flag++;
if (rpm_check(release:"SL4", reference:"selinux-policy-targeted-sources-1.17.30-2.150.el4")) flag++;

if (rpm_check(release:"SL5", reference:"bind-9.3.4-6.0.1.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.4-6.0.1.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.4-6.0.1.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.4-6.0.1.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.4-6.0.1.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.4-6.0.1.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.4-6.0.1.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.4-6.0.1.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-2.4.6-137.1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-devel-2.4.6-137.1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-mls-2.4.6-137.1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-strict-2.4.6-137.1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-targeted-2.4.6-137.1.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
