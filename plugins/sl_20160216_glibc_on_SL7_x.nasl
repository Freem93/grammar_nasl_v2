#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(88798);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-5229", "CVE-2015-7547");
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVA", value:"2016-A-0053");

  script_name(english:"Scientific Linux Security Update : glibc on SL7.x x86_64");
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
"A stack-based buffer overflow was found in the way the libresolv
library performed dual A/AAAA DNS queries. A remote attacker could
create a specially crafted DNS response which could cause libresolv to
crash or, potentially, execute code with the permissions of the user
running the library. Note: this issue is only exposed when libresolv
is called from the nss_dns NSS service module. (CVE-2015-7547)

It was discovered that the calloc implementation in glibc could return
memory areas which contain non-zero bytes. This could result in
unexpected application behavior such as hangs or crashes.
(CVE-2015-5229)

This update also fixes the following bugs :

  - The existing implementation of the 'free' function
    causes all memory pools beyond the first to return freed
    memory directly to the operating system as quickly as
    possible. This can result in performance degradation
    when the rate of free calls is very high. The first
    memory pool (the main pool) does provide a method to
    rate limit the returns via M_TRIM_THRESHOLD, but this
    method is not available to subsequent memory pools.

With this update, the M_TRIM_THRESHOLD method is extended to apply to
all memory pools, which improves performance for threads with very
high amounts of free calls and limits the number of 'madvise' system
calls. The change also increases the total transient memory usage by
processes because the trim threshold must be reached before memory can
be freed.

To return to the previous behavior, you can either set
M_TRIM_THRESHOLD using the 'mallopt' function, or set the
MALLOC_TRIM_THRESHOLD environment variable to 0.

  - On the little-endian variant of 64-bit IBM Power Systems
    (ppc64le), a bug in the dynamic loader could cause
    applications compiled with profiling enabled to fail to
    start with the error 'monstartup: out of memory'. The
    bug has been corrected and applications compiled for
    profiling now start correctly."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1602&L=scientific-linux-errata&F=&S=&P=15470
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?569a8160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-2.17-106.el7_2.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-common-2.17-106.el7_2.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-2.17-106.el7_2.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-common-2.17-106.el7_2.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-devel-2.17-106.el7_2.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-headers-2.17-106.el7_2.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-static-2.17-106.el7_2.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-utils-2.17-106.el7_2.4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nscd-2.17-106.el7_2.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
