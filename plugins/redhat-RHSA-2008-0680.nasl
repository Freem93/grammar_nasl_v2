#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0680. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33582);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-2375");
  script_osvdb_id(46930);
  script_xref(name:"RHSA", value:"2008:0680");

  script_name(english:"RHEL 4 : vsftpd (RHSA-2008:0680)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated vsftpd package that fixes a security issue and various bugs
is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

vsftpd (Very Secure File Transfer Protocol (FTP) daemon) is a secure
FTP server for Linux and Unix-like systems.

The version of vsftpd as shipped in Red Hat Enterprise Linux 4 when
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

* when uploading unique files, a bug in vsftpd caused the file to be
saved with a suffix '.1' even when no previous file with that name
existed. This issues is resolved in this package.

* when vsftpd was run through the init script, it was possible for the
init script to print an 'OK' message, even though the vsftpd may not
have started. The init script no longer produces a false verification
with this update.

* vsftpd only supported usernames with a maximum length of 32
characters. The updated package now supports usernames up to 128
characters long.

* a system flaw meant vsftpd output could become dependent on the
timing or sequence of other events, even when the 'lock_upload_files'
option was set. If a file, filename.ext, was being uploaded and a
second transfer of the file, filename.ext, was started before the
first transfer was finished, the resultant uploaded file was a corrupt
concatenation of the latter upload and the tail of the earlier upload.
With this updated package, vsftpd allows the earlier upload to
complete before overwriting with the latter upload, fixing the issue.

* the 'lock_upload_files' option was not documented in the manual
page. A new manual page describing this option is included in this
package.

* vsftpd did not support usernames that started with an underscore or
a period character. These special characters are now allowed at the
beginning of a username.

* when storing a unique file, vsftpd could cause an error for some
clients. This is rectified in this package.

* vsftpd init script was found to not be Linux Standards Base
compliant. This update corrects their exit codes to conform to the
standard.

All vsftpd users are advised to upgrade to this updated package, which
resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0680.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vsftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vsftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0680";
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
  if (rpm_check(release:"RHEL4", reference:"vsftpd-2.0.1-6.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vsftpd");
  }
}
