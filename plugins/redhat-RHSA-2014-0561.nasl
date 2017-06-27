#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0561. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74205);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2014-0015", "CVE-2014-0138");
  script_bugtraq_id(65270, 66457);
  script_xref(name:"RHSA", value:"2014:0561");

  script_name(english:"RHEL 6 : curl (RHSA-2014:0561)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

cURL provides the libcurl library and a command line tool for
downloading files from servers using various protocols, including
HTTP, FTP, and LDAP.

It was found that libcurl could incorrectly reuse existing connections
for requests that should have used different or no authentication
credentials, when using one of the following protocols: HTTP(S) with
NTLM authentication, LDAP(S), SCP, or SFTP. If an application using
the libcurl library connected to a remote server with certain
authentication credentials, this flaw could cause other requests to
use those same credentials. (CVE-2014-0015, CVE-2014-0138)

Red Hat would like to thank the cURL project for reporting these
issues. Upstream acknowledges Paras Sethia as the original reporter of
CVE-2014-0015 and Yehezkel Horowitz for discovering the security
impact of this issue, and Steve Holme as the original reporter of
CVE-2014-0138.

This update also fixes the following bugs :

* Previously, the libcurl library was closing a network socket without
first terminating the SSL connection using the socket. This resulted
in a write after close and consequent leakage of memory dynamically
allocated by the SSL library. An upstream patch has been applied on
libcurl to fix this bug. As a result, the write after close no longer
happens, and the SSL library no longer leaks memory. (BZ#1092479)

* Previously, the libcurl library did not implement a non-blocking SSL
handshake, which negatively affected performance of applications based
on libcurl's multi API. To fix this bug, the non-blocking SSL
handshake has been implemented by libcurl. With this update, libcurl's
multi API immediately returns the control back to the application
whenever it cannot read/write data from/to the underlying network
socket. (BZ#1092480)

* Previously, the curl package could not be rebuilt from sources due
to an expired cookie in the upstream test-suite, which runs during the
build. An upstream patch has been applied to postpone the expiration
date of the cookie, which makes it possible to rebuild the package
from sources again. (BZ#1092486)

* Previously, the libcurl library attempted to authenticate using
Kerberos whenever such an authentication method was offered by the
server. This caused problems when the server offered multiple
authentication methods and Kerberos was not the selected one. An
upstream patch has been applied on libcurl to fix this bug. Now
libcurl no longer uses Kerberos authentication if another
authentication method is selected. (BZ#1096797)

All curl users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
applications that use libcurl have to be restarted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0561.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0561";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"curl-7.19.7-37.el6_5.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"curl-7.19.7-37.el6_5.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"curl-7.19.7-37.el6_5.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"curl-debuginfo-7.19.7-37.el6_5.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libcurl-7.19.7-37.el6_5.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libcurl-devel-7.19.7-37.el6_5.3")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / libcurl-devel");
  }
}
