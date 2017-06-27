#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61348);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/09/27 11:14:26 $");

  script_cve_id("CVE-2011-4623");

  script_name(english:"Scientific Linux Security Update : rsyslog on SL6.x i386/x86_64");
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
"The rsyslog packages provide an enhanced, multi-threaded syslog
daemon.

A numeric truncation error, leading to a heap-based buffer overflow,
was found in the way the rsyslog imfile module processed text files
containing long lines. An attacker could use this flaw to crash the
rsyslogd daemon or, possibly, execute arbitrary code with the
privileges of rsyslogd, if they are able to cause a long line to be
written to a log file that rsyslogd monitors with imfile. The imfile
module is not enabled by default. (CVE-2011-4623)

Bug fixes :

  - Several variables were incorrectly deinitialized with
    Transport Layer Security (TLS) transport and keys in
    PKCS#8 format. The rsyslogd daemon aborted with a
    segmentation fault when keys in this format were
    provided. Now, the variables are correctly
    deinitialized.

  - Previously, the imgssapi plug-in initialization was
    incomplete. As a result, the rsyslogd daemon aborted
    when configured to provide a GSSAPI listener. Now, the
    plug-in is correctly initialized.

  - The fully qualified domain name (FQDN) for the localhost
    used in messages was the first alias found. This did not
    always produce the expected result on multihomed hosts.
    With this update, the algorithm uses the alias that
    corresponds to the hostname.

  - The gtls module leaked a file descriptor every time it
    was loaded due to an error in the GnuTLS library. No new
    files or network connections could be opened when the
    limit for the file descriptor count was reached. This
    update modifies the gtls module so that it is not
    unloaded during the process lifetime.

  - rsyslog could not override the hostname to set an
    alternative hostname for locally generated messages.
    Now, the local hostname can be overridden.

  - The rsyslogd init script did not pass the lock file path
    to the 'status' action. As a result, the lock file was
    ignored and a wrong exit code was returned. This update
    modifies the init script to pass the lock file to the
    'status' action. Now, the correct exit code is returned.

  - Data could be incorrectly deinitialized when rsyslogd
    was supplied with malformed spool files. The rsyslogd
    daemon could be aborted with a segmentation fault. This
    update modifies the underlying code to correctly
    deinitialize the data.

  - Previously, deinitialization of non-existent data could,
    in certain error cases, occur. As a result, rsyslogd
    could abort with a segmentation fault when rsyslog was
    configured to use a disk assisted queue without
    specifying a spool file. With this update, the error
    cases are handled gracefully.

  - The manual page wrongly stated that the '-d' option to
    turn on debugging caused the daemon to run in the
    foreground, which was misleading as the current behavior
    is to run in the background. Now, the manual page
    reflects the correct behavior.

  - rsyslog attempted to write debugging messages to
    standard output even when run in the background. This
    resulted in the debugging information being written to
    some other output. This was corrected and the debug
    messages are no longer written to standard output when
    run in the background.

  - The string buffer to hold the distinguished name (DN) of
    a certificate was too small. DNs with more than 128
    characters were not displayed. This update enlarges the
    buffer to process longer DNs.

Enhancements :

  - Support for rate limiting and multi-line message
    capability. Now, rsyslogd can limit the number of
    messages it accepts through a UNIX socket.

  - The addition of the '/etc/rsyslog.d/' configuration
    directory to supply syslog configuration files.

All users of rsyslog are advised to upgrade to these updated packages,
which upgrade rsyslog to version 5.8.10 and correct these issues and
add these enhancements. After installing this update, the rsyslog
daemon will be restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=3477
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd9057f2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
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
if (rpm_check(release:"SL6", reference:"rsyslog-5.8.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-debuginfo-5.8.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-gnutls-5.8.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-gssapi-5.8.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-mysql-5.8.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-pgsql-5.8.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-relp-5.8.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"rsyslog-snmp-5.8.10-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
