#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60409);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2007-5962");

  script_name(english:"Scientific Linux Security Update : vsftpd on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A memory leak was discovered in the vsftpd daemon. An attacker who is
able to connect to an FTP service, either as an authenticated or
anonymous user, could cause vsftpd to allocate all available memory if
the 'deny_file' option was enabled in vsftpd.conf. (CVE-2007-5962)

As well, this updated package fixes following bugs :

  - a race condition could occur even when the
    'lock_upload_files' option is set. When uploading two
    files simultaneously, the result was a combination of
    the two files. This resulted in uploaded files becoming
    corrupted. In these updated packages, uploading two
    files simultaneously will result in a file that is
    identical to the last uploaded file.

  - when the 'userlist_enable' option is used, failed log in
    attempts as a result of the user not being in the list
    of allowed users, or being in the list of denied users,
    will not be logged. In these updated packages, a new
    'userlist_log=YES' option can be configured in
    vsftpd.conf, which will log failed log in attempts in
    these situations.

  - vsftpd did not support usernames that started with an
    underscore or a period character. Usernames starting
    with an underscore or a period are supported in these
    updated packages.

  - using wildcards in conjunction with the 'ls' command did
    not return all the file names it should. For example, if
    you FTPed into a directory containing three files -- A1,
    A21 and A11 -- and ran the 'ls *1' command, only the
    file names A1 and A21 were returned. These updated
    packages use greedier code that continues to
    speculatively scan for items even after matches have
    been found.

  - when the 'user_config_dir' option is enabled in
    vsftpd.conf, and the user-specific configuration file
    did not exist, the following error occurred after a user
    entered their password during the log in process :

500 OOPS: reading non-root config file

This has been resolved in this updated package."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0805&L=scientific-linux-errata&T=0&P=1704
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecc7b517"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vsftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
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
if (rpm_check(release:"SL5", reference:"vsftpd-2.0.5-12.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
