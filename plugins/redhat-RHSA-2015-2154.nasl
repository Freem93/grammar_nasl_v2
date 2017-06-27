#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2154. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86933);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2014-5355", "CVE-2015-2694");
  script_osvdb_id(118567, 118568, 118569, 118570, 121429);
  script_xref(name:"RHSA", value:"2015:2154");

  script_name(english:"RHEL 7 : krb5 (RHSA-2015:2154)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix two security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Kerberos is a network authentication system, which can improve the
security of your network by eliminating the insecure practice of
sending passwords over the network in unencrypted form. It allows
clients and servers to authenticate to each other with the help of a
trusted third party, the Kerberos key distribution center (KDC).

It was found that the krb5_read_message() function of MIT Kerberos did
not correctly sanitize input, and could create invalid krb5_data
objects. A remote, unauthenticated attacker could use this flaw to
crash a Kerberos child process via a specially crafted request.
(CVE-2014-5355)

A flaw was found in the OTP kdcpreauth module of MIT kerberos. An
unauthenticated remote attacker could use this flaw to bypass the
requires_preauth flag on a client principal and obtain a ciphertext
encrypted in the principal's long-term key. This ciphertext could be
used to conduct an off-line dictionary attack against the user's
password. (CVE-2015-2694)

The krb5 packages have been upgraded to upstream version 1.13.2, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#1203889)

Notably, this update fixes the following bugs :

* Previously, the RADIUS support (libkrad) in krb5 was sending krb5
authentication for Transmission Control Protocol (TCP) transports
multiple times, accidentally using a code path intended to be used
only for unreliable transport types, for example User Datagram
Protocol (UDP) transports. A patch that fixes the problem by disabling
manual retries for reliable transports, such as TCP, has been applied,
and the correct code path is now used in this situation. (BZ#1251586)

* Attempts to use Kerberos single sign-on (SSO) to access SAP
NetWeaver systems sometimes failed. The SAP NetWeaver developer trace
displayed the following error message :

No credentials were supplied, or the credentials were unavailable or
inaccessible Unable to establish the security context

Querying SSO credential lifetime has been modified to trigger
credential acquisition, thus preventing the error from occurring. Now,
the user can successfully use Kerberos SSO for accessing SAP NetWeaver
systems. (BZ#1252454)

All krb5 users are advised to upgrade to these updated packages, which
correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2694.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2154.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2154";
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
  if (rpm_check(release:"RHEL7", reference:"krb5-debuginfo-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"krb5-devel-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"krb5-libs-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"krb5-pkinit-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"krb5-pkinit-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"krb5-server-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"krb5-server-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"krb5-server-ldap-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"krb5-server-ldap-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"krb5-workstation-1.13.2-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"krb5-workstation-1.13.2-10.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-pkinit / krb5-server / etc");
  }
}
