#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60517);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/05 21:24:24 $");

  script_cve_id("CVE-2009-0025");

  script_name(english:"Scientific Linux Security Update : bind on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"A flaw was discovered in the way BIND checked the return value of the
OpenSSL DSA_do_verify function. On systems using DNSSEC, a malicious
zone could present a malformed DSA certificate and bypass proper
certificate validation, allowing spoofing attacks. (CVE-2009-0025)

For users of Red Hat Enterprise Linux 3 this update also addresses a
bug which can cause BIND to occasionally exit with an assertion
failure.

After installing theupdate, BIND daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0901&L=scientific-linux-errata&T=0&P=924
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc6f2da1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/08");
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
if (rpm_check(release:"SL3", reference:"bind-9.2.4-23.el3")) flag++;
if (rpm_check(release:"SL3", reference:"bind-chroot-9.2.4-23.el3")) flag++;
if (rpm_check(release:"SL3", reference:"bind-devel-9.2.4-23.el3")) flag++;
if (rpm_check(release:"SL3", reference:"bind-libs-9.2.4-23.el3")) flag++;
if (rpm_check(release:"SL3", reference:"bind-utils-9.2.4-23.el3")) flag++;

if (rpm_check(release:"SL4", reference:"bind-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"bind-chroot-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"bind-devel-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"bind-libs-9.2.4-30.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"bind-utils-9.2.4-30.el4_7.1")) flag++;

if (rpm_check(release:"SL5", reference:"bind-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-chroot-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-devel-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libbind-devel-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-libs-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-sdb-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"bind-utils-9.3.4-6.0.3.P1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"caching-nameserver-9.3.4-6.0.3.P1.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
