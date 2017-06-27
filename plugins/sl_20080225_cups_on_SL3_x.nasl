#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60364);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-0596", "CVE-2008-0597", "CVE-2008-0882");

  script_name(english:"Scientific Linux Security Update : cups on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"SL 3 and SL 4 only A flaw was found in the way CUPS handled the
addition and removal of remote shared printers via IPP. A remote
attacker could send malicious UDP IPP packets causing the CUPS daemon
to attempt to dereference already freed memory and crash.
(CVE-2008-0597)

A memory management flaw was found in the way CUPS handled the
addition and removal of remote shared printers via IPP. When shared
printer was removed, allocated memory was not properly freed, leading
to a memory leak possibly causing CUPS daemon crash after exhausting
available memory. (CVE-2008-0596)

SL 5 only A flaw was found in the way CUPS handles the addition and
removal of remote shared printers via IPP. A remote attacker could
send malicious UDP IPP packets causing the CUPS daemon to crash.
(CVE-2008-0882)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0802&L=scientific-linux-errata&T=0&P=804
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23505281"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/25");
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
if (rpm_check(release:"SL3", reference:"cups-1.1.17-13.3.51")) flag++;
if (rpm_check(release:"SL3", reference:"cups-devel-1.1.17-13.3.51")) flag++;
if (rpm_check(release:"SL3", reference:"cups-libs-1.1.17-13.3.51")) flag++;

if (rpm_check(release:"SL4", reference:"cups-1.1.22-0.rc1.9.20.2.el4_6.5")) flag++;
if (rpm_check(release:"SL4", reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_6.5")) flag++;
if (rpm_check(release:"SL4", reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_6.5")) flag++;

if (rpm_check(release:"SL5", reference:"cups-1.2.4-11.14.el5_1.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.2.4-11.14.el5_1.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.2.4-11.14.el5_1.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.2.4-11.14.el5_1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
