#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60962);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/02 02:32:17 $");

  script_cve_id("CVE-2009-4565");
  script_xref(name:"IAVA", value:"2010-A-0002");

  script_name(english:"Scientific Linux Security Update : sendmail on SL4.x i386/x86_64");
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
"A flaw was found in the way sendmail handled NUL characters in the
CommonName field of X.509 certificates. An attacker able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority could trick sendmail into accepting it by mistake, allowing
the attacker to perform a man-in-the-middle attack or bypass intended
client certificate authentication. (CVE-2009-4565)

The CVE-2009-4565 issue only affected configurations using TLS with
certificate verification and CommonName checking enabled, which is not
a typical configuration.

This update also fixes the following bugs :

  - Previously, sendmail did not correctly handle mail
    messages that had a long first header line. A line with
    more than 2048 characters was split, causing the part of
    the line exceeding the limit, as well as all of the
    following mail headers, to be incorrectly handled as the
    message body. (BZ#499450)

  - When an SMTP-sender is sending mail data to sendmail, it
    may spool that data to a file in the mail queue. It was
    found that, if the SMTP-sender stopped sending data and
    a timeout occurred, the file may have been left stalled
    in the mail queue, instead of being deleted. This update
    may not correct this issue for every situation and
    configuration. Refer to the Notes section for further
    information. (BZ#434645)

  - Previously, the sendmail macro MAXHOSTNAMELEN used 64
    characters as the limit for the hostname length.
    However, in some cases, it was used against an FQDN
    length, which has a maximum length of 255 characters.
    With this update, the MAXHOSTNAMELEN limit has been
    changed to 255. (BZ#485380)

After installing this update, sendmail will be restarted
automatically.

Notes: As part of the fix for BZ#434645, a script called purge-mqueue
is shipped with this update. It is located in the /usr/share/sendmail/
directory. The primary purpose of this script is a one-time clean up
of the mqueue from stalled files that were created before the
installation of this update. By default, the script removes all files
from /var/spool/mqueue/ that have an atime older than one month. It
requires the tmpwatch package to be installed. If you have stalled
files in your mqueue you can run this script or clean them manually.
It is also possible to use this script as a cron job (for example, by
copying it to /etc/cron.daily/), but it should not be needed in most
cases, because this update should prevent the creation of new stalled
files."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1102&L=scientific-linux-errata&T=0&P=1847
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6beab5b1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=434645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=485380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=499450"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (rpm_check(release:"SL4", reference:"sendmail-8.13.1-6.el4")) flag++;
if (rpm_check(release:"SL4", reference:"sendmail-cf-8.13.1-6.el4")) flag++;
if (rpm_check(release:"SL4", reference:"sendmail-devel-8.13.1-6.el4")) flag++;
if (rpm_check(release:"SL4", reference:"sendmail-doc-8.13.1-6.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
