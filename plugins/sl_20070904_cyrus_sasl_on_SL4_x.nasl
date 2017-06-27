#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60245);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2006-1721");

  script_name(english:"Scientific Linux Security Update : cyrus-sasl on SL4.x, SL3.x i386/x86_64");
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
"A bug was found in cyrus-sasl's DIGEST-MD5 authentication mechanism.
As part of the DIGEST-MD5 authentication exchange, the client is
expected to send a specific set of information to the server. If one
of these items (the 'realm') was not sent or was malformed, it was
possible for a remote unauthenticated attacker to cause a denial of
service (segmentation fault) on the server. (CVE-2006-1721)

This errata also fixes the following bugs in Scientific Linux 4 :

  - the Kerberos 5 library included in Red Hat Enterprise
    Linux 4 was not thread safe. This update adds
    functionality which allows it to be used safely in a
    threaded application.

  - several memory leak bugs were fixed in cyrus-sasl's
    DIGEST-MD5 authentication plug-in.

  - /dev/urandom is now used by default on systems which
    don't support hwrandom. Previously, dev/random was the
    default.

  - cyrus-sasl needs zlib-devel to build properly. This
    dependency information is now included in the package."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0709&L=scientific-linux-errata&T=0&P=429
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7b71855"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/04");
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
if (rpm_check(release:"SL3", reference:"cyrus-sasl-2.1.15-15")) flag++;
if (rpm_check(release:"SL3", reference:"cyrus-sasl-devel-2.1.15-15")) flag++;
if (rpm_check(release:"SL3", reference:"cyrus-sasl-gssapi-2.1.15-15")) flag++;
if (rpm_check(release:"SL3", reference:"cyrus-sasl-md5-2.1.15-15")) flag++;
if (rpm_check(release:"SL3", reference:"cyrus-sasl-plain-2.1.15-15")) flag++;

if (rpm_check(release:"SL4", reference:"cyrus-sasl-2.1.19-14")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-sasl-devel-2.1.19-14")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-sasl-gssapi-2.1.19-14")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-sasl-md5-2.1.19-14")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-sasl-ntlm-2.1.19-14")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-sasl-plain-2.1.19-14")) flag++;
if (rpm_check(release:"SL4", reference:"cyrus-sasl-sql-2.1.19-14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
