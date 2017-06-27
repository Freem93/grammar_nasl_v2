#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61136);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-3208");

  script_name(english:"Scientific Linux Security Update : cyrus-imapd on SL4.x, SL5.x, SL6.x i386/x86_64");
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
"The cyrus-imapd packages contain a high-performance mail server with
IMAP, POP3, NNTP, and Sieve support.

A buffer overflow flaw was found in the cyrus-imapd NNTP server,
nntpd. A remote user able to use the nntpd service could use this flaw
to crash the nntpd child process or, possibly, execute arbitrary code
with the privileges of the cyrus user. (CVE-2011-3208)

Users of cyrus-imapd are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, cyrus-imapd will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=2326
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e74323ee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/19");
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
if (rpm_check(release:"SL4", reference:"cyrus-imapd-2.2.12-16.el4")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-debuginfo-2.2.12-16.el4")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-devel-2.2.12-16.el4")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-murder-2.2.12-16.el4")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-nntp-2.2.12-16.el4")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-utils-2.2.12-16.el4")) flag++;
if (rpm_check(release:"SL4", reference:"perl-Cyrus-2.2.12-16.el4")) flag++;

if (rpm_check(release:"SL5", reference:"cyrus-imapd-2.3.7-12.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"cyrus-imapd-debuginfo-2.3.7-12.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"cyrus-imapd-devel-2.3.7-12.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"cyrus-imapd-perl-2.3.7-12.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"cyrus-imapd-utils-2.3.7-12.el5_7.1")) flag++;

if (rpm_check(release:"SL6", reference:"cyrus-imapd-2.3.16-6.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"cyrus-imapd-debuginfo-2.3.16-6.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"cyrus-imapd-devel-2.3.16-6.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"cyrus-imapd-utils-2.3.16-6.el6_1.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
