#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60774);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/02 02:32:17 $");

  script_cve_id("CVE-2006-7176", "CVE-2009-4565");
  script_xref(name:"IAVA", value:"2010-A-0002");

  script_name(english:"Scientific Linux Security Update : sendmail on SL5.x i386/x86_64");
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
"The configuration of sendmail in Scientific Linux was found to not
reject the 'localhost.localdomain' domain name for email messages that
come from external hosts. This could allow remote attackers to
disguise spoofed messages. (CVE-2006-7176)

A flaw was found in the way sendmail handled NUL characters in the
CommonName field of X.509 certificates. An attacker able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority could trick sendmail into accepting it by mistake, allowing
the attacker to perform a man-in-the-middle attack or bypass intended
client certificate authentication. (CVE-2009-4565)

Note: The CVE-2009-4565 issue only affected configurations using TLS
with certificate verification and CommonName checking enabled, which
is not a typical configuration.

This update also fixes the following bugs :

  - sendmail was unable to parse files specified by the
    ServiceSwitchFile option which used a colon as a
    separator. (BZ#512871)

  - sendmail incorrectly returned a zero exit code when free
    space was low. (BZ#299951)

  - the sendmail manual page had a blank space between the
    -qG option and parameter. (BZ#250552)

  - the comments in the sendmail.mc file specified the wrong
    path to SSL certificates. (BZ#244012)

  - the sendmail packages did not provide the MTA
    capability. (BZ#494408)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=917
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5569d4dd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=244012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=250552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=299951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=494408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512871"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"SL5", reference:"sendmail-8.13.8-8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sendmail-cf-8.13.8-8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sendmail-devel-8.13.8-8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sendmail-doc-8.13.8-8.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
