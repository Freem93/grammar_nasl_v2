#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1287. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84937);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2014-2015");
  script_bugtraq_id(65581);
  script_osvdb_id(103421);
  script_xref(name:"RHSA", value:"2015:1287");

  script_name(english:"RHEL 6 : freeradius (RHSA-2015:1287)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

A stack-based buffer overflow was found in the way the FreeRADIUS
rlm_pap module handled long password hashes. An attacker able to make
radiusd process a malformed password hash could cause the daemon to
crash. (CVE-2014-2015)

The freeradius packages have been upgraded to upstream version 2.2.6,
which provides a number of bug fixes and enhancements over the
previous version, including :

* The number of dictionaries have been updated.

* This update implements several Extensible Authentication Protocol
(EAP) improvements.

* A number of new expansions have been added, including:
%{randstr:...}, %{hex:...}, %{sha1:...}, %{base64:...},
%{tobase64:...}, and %{base64tohex:...}.

* Hexadecimal numbers (0x...) are now supported in %{expr:...}
expansions.

* This update adds operator support to the rlm_python module.

* The Dynamic Host Configuration Protocol (DHCP) and DHCP relay code
have been finalized.

* This update adds the rlm_cache module to cache arbitrary attributes.

For a complete list of bug fixes and enhancements provided by this
rebase, see the freeradius changelog linked to in the References
section.

(BZ#1078736)

This update also fixes the following bugs :

* The /var/log/radius/radutmp file was configured to rotate at
one-month intervals, even though this was unnecessary. This update
removes /var/log/radius/radutmp from the installed logrotate utility
configuration in the /etc/logrotate.d/radiusd file, and
/var/log/radius/radutmp is no longer rotated. (BZ#904578)

* The radiusd service could not write the output file created by the
raddebug utility. The raddebug utility now sets appropriate ownership
to the output file, allowing radiusd to write the output. (BZ#921563)

* After starting raddebug using the 'raddebug -t 0' command, raddebug
exited immediately. A typo in the special case comparison has been
fixed, and raddebug now runs for 11.5 days in this situation.
(BZ#921567)

* MS-CHAP authentication failed when the User-Name and
MS-CHAP-User-Name attributes used different encodings, even when the
user provided correct credentials. Now, MS-CHAP authentication
properly handles mismatching character encodings. Authentication with
correct credentials no longer fails in this situation. (BZ#1060319)

* Automatically generated default certificates used the SHA-1
algorithm message digest, which is considered insecure. The default
certificates now use the more secure SHA-256 algorithm message digest.
(BZ#1135439)

* During the Online Certificate Status Protocol (OCSP) validation,
radiusd terminated unexpectedly with a segmentation fault after
attempting to access the next update field that was not provided by
the OCSP responder. Now, radiusd does not crash in this situation and
instead continues to complete the OCSP validation. (BZ#1142669)

* Prior to this update, radiusd failed to work with some of the more
recent MikroTIK attributes, because the installed directory.mikrotik
file did not include them. This update adds MikroTIK attributes with
IDs up to 22 to dictionary.mikrotik, and radiusd now works as expected
with these attributes. (BZ#1173388)

Users of freeradius are advised to upgrade to these updated packages,
which correct these issues and add these enhancements. After
installing this update, the radiusd service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2015.html"
  );
  # https://raw.githubusercontent.com/FreeRADIUS/freeradius-server/v3.0.x/doc/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?847a81b0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1287.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1287";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-debuginfo-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-debuginfo-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-debuginfo-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-krb5-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-krb5-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-krb5-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-ldap-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-ldap-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-ldap-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-mysql-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-mysql-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-mysql-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-perl-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-perl-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-perl-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-postgresql-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-postgresql-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-postgresql-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-python-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-python-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-python-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-unixODBC-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-unixODBC-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-unixODBC-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"freeradius-utils-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"freeradius-utils-2.2.6-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"freeradius-utils-2.2.6-4.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-debuginfo / freeradius-krb5 / etc");
  }
}
