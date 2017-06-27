#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0999. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55643);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2007-6200");
  script_bugtraq_id(26639);
  script_xref(name:"RHSA", value:"2011:0999");

  script_name(english:"RHEL 5 : rsync (RHSA-2011:0999)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rsync package that fixes one security issue, several bugs,
and adds enhancements is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

rsync is a program for synchronizing files over a network.

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

* The rsync package has been upgraded to upstream version 3.0.6, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#339971)

* When running an rsync daemon that was receiving files, a deferred
info, error or log message could have been sent directly to the sender
instead of being handled by the 'rwrite()' function in the generator.
Also, under certain circumstances, a deferred info or error message
from the receiver could have bypassed the log file and could have been
sent only to the client process. As a result, an 'unexpected tag 3'
fatal error could have been displayed. These problems have been fixed
in this update so that an rsync daemon receiving files now works as
expected. (BZ#471182)

* Prior to this update, the rsync daemon called a number of
timezone-using functions after doing a chroot. As a result, certain C
libraries were unable to generate proper timestamps from inside a
chrooted daemon. This bug has been fixed in this update so that the
rsync daemon now calls the respective timezone-using functions prior
to doing a chroot, and proper timestamps are now generated as
expected. (BZ#575022)

* When running rsync under a non-root user with the '-A' ('--acls')
option and without using the '--numeric-ids' option, if there was an
Access Control List (ACL) that included a group entry for a group that
the respective user was not a member of on the receiving side, the
'acl_set_file()' function returned an invalid argument value
('EINVAL'). This was caused by rsync mistakenly mapping the group name
to the Group ID 'GID_NONE' ('-1'), which failed. The bug has been
fixed in this update so that no invalid argument is returned and rsync
works as expected. (BZ#616093)

* When creating a sparse file that was zero blocks long, the 'rsync
--sparse' command did not properly truncate the sparse file at the end
of the copy transaction. As a result, the file size was bigger than
expected. This bug has been fixed in this update by properly
truncating the file so that rsync now copies such files as expected.
(BZ#530866)

* Under certain circumstances, when using rsync in daemon mode, rsync
generator instances could have entered an infinitive loop, trying to
write an error message for the receiver to an invalid socket. This
problem has been fixed in this update by adding a new sibling message:
when the receiver is reporting a socket-read error, the generator will
notice this fact and avoid writing an error message down the socket,
allowing it to close down gracefully when the pipe from the receiver
closes. (BZ#690148)

* Prior to this update, there were missing deallocations found in the
'start_client()' function. This bug has been fixed in this update and
no longer occurs. (BZ#700450)

All users of rsync are advised to upgrade to this updated package,
which resolves these issues and adds enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rsync.samba.org/security.html#s3_0_0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0999.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rsync package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0999";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"rsync-3.0.6-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"rsync-3.0.6-4.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"rsync-3.0.6-4.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsync");
  }
}
