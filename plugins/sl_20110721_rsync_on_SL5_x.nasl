#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61092);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2007-6200");

  script_name(english:"Scientific Linux Security Update : rsync on SL5.x i386/x86_64");
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
"rsync is a program for synchronizing files over a network.

A flaw was found in the way the rsync daemon handled the 'filter',
'exclude', and 'exclude from' options, used for hiding files and
preventing access to them from rsync clients. A remote attacker could
use this flaw to bypass those restrictions by using certain command
line options and symbolic links, allowing the attacker to overwrite
those files if they knew their file names and had write access to
them. (CVE-2007-6200)

Note: This issue only affected users running rsync as a writable
daemon: 'read only' set to 'false' in the rsync configuration file
(for example, '/etc/rsyncd.conf'). By default, this option is set to
'true'.

This update also fixes the following bugs :

  - The rsync package has been upgraded to upstream version
    3.0.6, which provides a number of bug fixes and
    enhancements over the previous version.

  - When running an rsync daemon that was receiving files, a
    deferred info, error or log message could have been sent
    directly to the sender instead of being handled by the
    'rwrite()' function in the generator. Also, under
    certain circumstances, a deferred info or error message
    from the receiver could have bypassed the log file and
    could have been sent only to the client process. As a
    result, an 'unexpected tag 3' fatal error could have
    been displayed. These problems have been fixed in this
    update so that an rsync daemon receiving files now works
    as expected.

  - Prior to this update, the rsync daemon called a number
    of timezone-using functions after doing a chroot. As a
    result, certain C libraries were unable to generate
    proper timestamps from inside a chrooted daemon. This
    bug has been fixed in this update so that the rsync
    daemon now calls the respective timezone-using functions
    prior to doing a chroot, and proper timestamps are now
    generated as expected.

  - When running rsync under a non-root user with the '-A'
    ('--acls') option and without using the '--numeric-ids'
    option, if there was an Access Control List (ACL) that
    included a group entry for a group that the respective
    user was not a member of on the receiving side, the
    'acl_set_file()' function returned an invalid argument
    value ('EINVAL'). This was caused by rsync mistakenly
    mapping the group name to the Group ID 'GID_NONE'
    ('-1'), which failed. The bug has been fixed in this
    update so that no invalid argument is returned and rsync
    works as expected.

  - When creating a sparse file that was zero blocks long,
    the 'rsync

  - --sparse' command did not properly truncate the sparse
    file at the end of the copy transaction. As a result,
    the file size was bigger than expected. This bug has
    been fixed in this update by properly truncating the
    file so that rsync now copies such files as expected.

  - Under certain circumstances, when using rsync in daemon
    mode, rsync generator instances could have entered an
    infinitive loop, trying to write an error message for
    the receiver to an invalid socket. This problem has been
    fixed in this update by adding a new sibling message:
    when the receiver is reporting a socket-read error, the
    generator will notice this fact and avoid writing an
    error message down the socket, allowing it to close down
    gracefully when the pipe from the receiver closes.

  - Prior to this update, there were missing deallocations
    found in the 'start_client()' function. This bug has
    been fixed in this update and no longer occurs.

All users of rsync are advised to upgrade to this updated package,
which resolves these issues and adds enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1107&L=scientific-linux-errata&T=0&P=2064
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d012b130"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rsync and / or rsync-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
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
if (rpm_check(release:"SL5", reference:"rsync-3.0.6-4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"rsync-debuginfo-3.0.6-4.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
