#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60456);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-2375");

  script_name(english:"Scientific Linux Security Update : vsftpd on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of vsftpd as shipped in Red Hat Enterprise Linux 4 when
used in combination with Pluggable Authentication Modules (PAM) had a
memory leak on an invalid authentication attempt. Since vsftpd prior
to version 2.0.5 allows any number of invalid attempts on the same
connection this memory leak could lead to an eventual DoS.
(CVE-2008-2375)

This update mitigates this security issue by including a backported
patch which terminates a session after a given number of failed log in
attempts. The default number of attempts is 3 and this can be
configured using the 'max_login_fails' directive.

This package also addresses the following bugs :

  - when uploading unique files, a bug in vsftpd caused the
    file to be saved with a suffix '.1' even when no
    previous file with that name existed. This issues is
    resolved in this package.

  - when vsftpd was run through the init script, it was
    possible for the init script to print an 'OK' message,
    even though the vsftpd may not have started. The init
    script no longer produces a false verification with this
    update.

  - vsftpd only supported usernames with a maximum length of
    32 characters. The updated package now supports
    usernames up to 128 characters long.

  - a system flaw meant vsftpd output could become dependent
    on the timing or sequence of other events, even when the
    'lock_upload_files' option was set. If a file,
    filename.ext, was being uploaded and a second transfer
    of the file, filename.ext, was started before the first
    transfer was finished, the resultant uploaded file was a
    corrupt concatenation of the latter upload and the tail
    of the earlier upload. With this updated package, vsftpd
    allows the earlier upload to complete before overwriting
    with the latter upload, fixing the issue.

  - the 'lock_upload_files' option was not documented in the
    manual page. A new manual page describing this option is
    included in this package.

  - vsftpd did not support usernames that started with an
    underscore or a period character. These special
    characters are now allowed at the beginning of a
    username.

  - when storing a unique file, vsftpd could cause an error
    for some clients. This is rectified in this package.

  - vsftpd init script was found to not be Linux Standards
    Base compliant. This update corrects their exit codes to
    conform to the standard."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=2744
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6171d0d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vsftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/24");
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
if (rpm_check(release:"SL4", reference:"vsftpd-2.0.1-6.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
