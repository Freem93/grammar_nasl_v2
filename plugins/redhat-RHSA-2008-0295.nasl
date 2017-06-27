#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0295. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32422);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2007-5962");
  script_bugtraq_id(29322);
  script_xref(name:"RHSA", value:"2008:0295");

  script_name(english:"RHEL 5 : vsftpd (RHSA-2008:0295)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated vsftpd package that fixes a security issue and several bugs
is now available for Red Hat Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The vsftpd package includes a Very Secure File Transfer Protocol (FTP)
daemon.

A memory leak was discovered in the vsftpd daemon. An attacker who is
able to connect to an FTP service, either as an authenticated or
anonymous user, could cause vsftpd to allocate all available memory if
the 'deny_file' option was enabled in vsftpd.conf. (CVE-2007-5962)

As well, this updated package fixes following bugs :

* a race condition could occur even when the 'lock_upload_files'
option is set. When uploading two files simultaneously, the result was
a combination of the two files. This resulted in uploaded files
becoming corrupted. In these updated packages, uploading two files
simultaneously will result in a file that is identical to the last
uploaded file.

* when the 'userlist_enable' option is used, failed log in attempts as
a result of the user not being in the list of allowed users, or being
in the list of denied users, will not be logged. In these updated
packages, a new 'userlist_log=YES' option can be configured in
vsftpd.conf, which will log failed log in attempts in these
situations.

* vsftpd did not support usernames that started with an underscore or
a period character. Usernames starting with an underscore or a period
are supported in these updated packages.

* using wildcards in conjunction with the 'ls' command did not return
all the file names it should. For example, if you FTPed into a
directory containing three files -- A1, A21 and A11 -- and ran the 'ls
*1' command, only the file names A1 and A21 were returned. These
updated packages use greedier code that continues to speculatively
scan for items even after matches have been found.

* when the 'user_config_dir' option is enabled in vsftpd.conf, and the
user-specific configuration file did not exist, the following error
occurred after a user entered their password during the log in 
process :

500 OOPS: reading non-root config file

This has been resolved in this updated package.

All vsftpd users are advised to upgrade to this updated package, which
resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5962.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0295.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vsftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vsftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0295";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"vsftpd-2.0.5-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"vsftpd-2.0.5-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vsftpd-2.0.5-12.el5")) flag++;

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
