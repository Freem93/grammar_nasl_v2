#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0715. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33583);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2007-5794");
  script_bugtraq_id(26452);
  script_xref(name:"RHSA", value:"2008:0715");

  script_name(english:"RHEL 4 : nss_ldap (RHSA-2008:0715)");
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

A race condition was discovered in nss_ldap, which affected certain
applications that make LDAP connections, such as Dovecot. This could
cause nss_ldap to answer a request for information about one user with
the information about a different user. (CVE-2007-5794)

As well, this updated package fixes the following bugs :

* in certain situations, on Itanium(R) architectures, when an
application performed an LDAP lookup for a highly populated group, for
example, containing more than 150 members, the application crashed, or
may have caused a segmentation fault. As well, this issue may have
caused commands, such as 'ls', to return a 'ber_free_buf: Assertion'
error.

* when an application enumerated members of a netgroup, the nss_ldap
module returned a successful status result and the netgroup name, even
when the netgroup did not exist. This behavior was not consistent with
other modules. In this updated package, nss_ldap no longer returns a
successful status when the netgroup does not exist.

* in master and slave server environments, with systems that were
configured to use a read-only directory server, if user log in
attempts were denied because their passwords had expired, and users
attempted to immediately change their passwords, the replication
server returned an LDAP referral, instructing the pam_ldap module to
resissue its request to a different server; however, the pam_ldap
module failed to do so. In these situations, an error such as the
following occurred :

LDAP password information update failed: Can't contact LDAP server
Insufficient 'write' privilege to the 'userPassword' attribute of
entry [entry]

In this updated package, password changes are allowed when binding
against a slave server, which resolves this issue.

* when a system used a directory server for naming information, and
'nss_initgroups_ignoreusers root' was configured in '/etc/ldap.conf',
dbus-daemon-1 would hang. Running the 'service messagebus start'
command did not start the service, and it did not fail, which would
stop the boot process if it was not cancelled.

As well, this updated package upgrades nss_ldap to the version as
shipped with Red Hat Enterprise Linux 5.

Users of nss_ldap are advised to upgrade to this updated package,
which resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5794.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0715.html"
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
  rhsa = "RHSA-2008:0715";
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
  if (rpm_check(release:"RHEL4", reference:"nss_ldap-253-5.el4")) flag++;

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
