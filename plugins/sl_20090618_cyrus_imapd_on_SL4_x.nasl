#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60601);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2009-0688");

  script_name(english:"Scientific Linux Security Update : cyrus-imapd on SL4.x, SL5.x i386/x86_64");
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
"It was discovered that the Cyrus SASL library (cyrus-sasl) does not
always reliably terminate output from the sasl_encode64() function
used by programs using this library. The Cyrus IMAP server
(cyrus-imapd) relied on this function's output being properly
terminated. Under certain conditions, improperly terminated output
from sasl_encode64() could, potentially, cause cyrus-imapd to crash,
disclose portions of its memory, or lead to SASL authentication
failures. (CVE-2009-0688)

After installing the update, cyrus-imapd will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0906&L=scientific-linux-errata&T=0&P=1449
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aaf508eb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/18");
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
if (rpm_check(release:"SL4", reference:"cyrus-imapd-2.2.12-10.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-devel-2.2.12-10.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-murder-2.2.12-10.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-nntp-2.2.12-10.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-imapd-utils-2.2.12-10.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"perl-Cyrus-2.2.12-10.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"cyrus-imapd-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"cyrus-imapd-devel-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"cyrus-imapd-perl-2.3.7-2.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"cyrus-imapd-utils-2.3.7-2.el5_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
