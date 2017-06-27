#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70391);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/11 10:51:01 $");

  script_cve_id("CVE-2013-0219");

  script_name(english:"Scientific Linux Security Update : sssd on SL5.x i386/x86_64");
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
"A race condition was found in the way SSSD copied and removed user
home directories. A local attacker who is able to write into the home
directory of a different user who is being removed could use this flaw
to perform symbolic link attacks, possibly allowing them to modify and
delete arbitrary files with the privileges of the root user.
(CVE-2013-0219)

This update also fixes the following bugs :

  - After a paging control was used, memory in the sssd_be
    process was never freed which led to the growth of the
    sssd_be process memory usage over time. To fix this bug,
    the paging control was deallocated after use, and thus
    the memory usage of the sssd_be process no longer grows.

  - If the sssd_be process was terminated and recreated
    while there were authentication requests pending, the
    sssd_pam process did not recover correctly and did not
    reconnect to the new sssd_be process. Consequently, the
    sssd_pam process was seemingly blocked and did not
    accept any new authentication requests. The sssd_pam
    process has been fixes so that it reconnects to the new
    instance of the sssd_be process after the original one
    terminated unexpectedly. Even after a crash and
    reconnect, the sssd_pam process now accepts new
    authentication requests.

  - When the sssd_be process hung for a while, it was
    terminated and a new instance was created. If the old
    instance did not respond to the TERM signal and
    continued running, SSSD terminated unexpectedly. As a
    consequence, the user could not log in. SSSD now keeps
    track of sssd_be subprocesses more effectively, making
    the restarts of sssd_be more reliable in such scenarios.
    Users can now log in whenever the sssd_be is restarted
    and becomes unresponsive.

  - In case the processing of an LDAP request took longer
    than the client timeout upon completing the request (60
    seconds by default), the PAM client could have accessed
    memory that was previously freed due to the client
    timeout being reached. As a result, the sssd_pam process
    terminated unexpectedly with a segmentation fault. SSSD
    now ignores an LDAP request result when it detects that
    the set timeout of this request has been reached. The
    sssd_pam process no longer crashes in the aforementioned
    scenario.

  - When there was a heavy load of users and groups to be
    saved in cache, SSSD experienced a timeout.
    Consequently, NSS did not start the backup process
    properly and it was impossible to log in. A patch has
    been provided to fix this bug. The SSSD daemon now
    remains responsive and the login continues as expected.

  - SSSD kept the file descriptors to the log files open.
    Consequently, on occasions like moving the actual log
    file and restarting the back end, SSSD still kept the
    file descriptors open. SSSD now closes the file
    descriptor after the child process execution; after a
    successful back end start, the file descriptor to log
    files is closed.

  - While performing access control in the Identity
    Management back end, SSSD erroneously downloaded the
    'member' attribute from the server and then attempted to
    use it in the cache verbatim. Consequently, the cache
    attempted to use the 'member' attribute values as if
    they were pointing to the local cache which was CPU
    intensive. The member attribute when processing host
    groups is no longer downloaded and processed. Moreover,
    the login process is reasonably fast even with large
    host groups."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=1052
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2036f6ae"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libipa_hbac-1.5.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libipa_hbac-devel-1.5.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libipa_hbac-python-1.5.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-1.5.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-client-1.5.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-debuginfo-1.5.1-70.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-tools-1.5.1-70.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
