#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0389. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32426);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2007-5794");
  script_bugtraq_id(26452);
  script_xref(name:"RHSA", value:"2008:0389");

  script_name(english:"RHEL 5 : nss_ldap (RHSA-2008:0389)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated nss_ldap package that fixes a security issue and several
bugs is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The nss_ldap package contains the nss_ldap and pam_ldap modules. The
nss_ldap module is a plug-in which allows applications to retrieve
information about users and groups from a directory server. The
pam_ldap module allows PAM-aware applications to use a directory
server to verify user passwords.

A race condition was discovered in nss_ldap which affected certain
applications which make LDAP connections, such as Dovecot. This could
cause nss_ldap to answer a request for information about one user with
information about a different user. (CVE-2007-5794)

In addition, these updated packages fix the following bugs :

* a build error prevented the nss_ldap module from being able to use
DNS to discover the location of a directory server. For example, when
the /etc/nsswitch.conf configuration file was configured to use
'ldap', but no 'host' or 'uri' option was configured in the
/etc/ldap.conf configuration file, no directory server was contacted,
and no results were returned.

* the 'port' option in the /etc/ldap.conf configuration file on client
machines was ignored. For example, if a directory server which you
were attempting to use was listening on a non-default port (i.e. not
ports 389 or 636), it was only possible to use that directory server
by including the port number in the 'uri' option. In this updated
package, the 'port' option works as expected.

* pam_ldap failed to change an expired password if it had to follow a
referral to do so, which could occur, for example, when using a slave
directory server in a replicated environment. An error such as the
following occurred after entering a new password: 'LDAP password
information update failed: Can't contact LDAP server Insufficient
'write' privilege to the 'userPassword' attribute'

This has been resolved in this updated package.

* when the 'pam_password exop_send_old' password-change method was
configured in the /etc/ldap.conf configuration file, a logic error in
the pam_ldap module caused client machines to attempt to change a
user's password twice. First, the pam_ldap module attempted to change
the password using the 'exop' request, and then again using an LDAP
modify request.

* on Red Hat Enterprise Linux 5.1, rebuilding nss_ldap-253-5.el5 when
the krb5-*-1.6.1-17.el5 packages were installed failed due to an error
such as the following :

+ /builddir/build/SOURCES/dlopen.sh ./nss_ldap-253/nss_ldap.so
dlopen() of '././nss_ldap-253/nss_ldap.so' failed:
./././nss_ldap-253/nss_ldap.so: undefined symbol: request_key error:
Bad exit status from /var/tmp/rpm-tmp.62652 (%build)

The missing libraries have been added, which resolves this issue.

When recursively enumerating the set of members in a given group, the
module would allocate insufficient space for storing the set of member
names if the group itself contained other groups, thus corrupting the
heap. This update includes a backported fix for this bug.

Users of nss_ldap should upgrade to these updated packages, which
contain backported patches to correct this issue and fix these bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5794.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0389.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss_ldap package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_ldap");
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
  rhsa = "RHSA-2008:0389";
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
  if (rpm_check(release:"RHEL5", reference:"nss_ldap-253-12.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss_ldap");
  }
}
