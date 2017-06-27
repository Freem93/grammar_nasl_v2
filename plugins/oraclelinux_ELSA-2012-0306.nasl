#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0306 and 
# Oracle Linux Security Advisory ELSA-2012-0306 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68477);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2011-1526");
  script_bugtraq_id(48571, 51182);
  script_osvdb_id(73617);
  script_xref(name:"RHSA", value:"2012:0306");

  script_name(english:"Oracle Linux 5 : krb5 (ELSA-2012-0306)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0306 :

Updated krb5 packages that fix one security issue and various bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third-party, the Key Distribution Center (KDC).

It was found that ftpd, a Kerberos-aware FTP server, did not properly
drop privileges. On Red Hat Enterprise Linux 5, the ftpd daemon did
not check for the potential failure of the effective group ID change
system call. If the group ID change failed, a remote FTP user could
use this flaw to gain unauthorized read or write access to files that
are owned by the root group. (CVE-2011-1526)

Red Hat would like to thank the MIT Kerberos project for reporting
this issue. Upstream acknowledges Tim Zingelman as the original
reporter.

This update also fixes the following bugs :

* Due to a mistake in the Kerberos libraries, a client could fail to
contact a Key Distribution Center (KDC) or terminate unexpectedly if
the client had already more than 1024 file descriptors in use. This
update backports modifications to the Kerberos libraries and the
libraries use the poll() function instead of the select() function, as
poll() does not have this limitation. (BZ#701444)

* The KDC failed to release memory when processing a TGS
(ticket-granting server) request from a client if the client request
included an authenticator with a subkey. As a result, the KDC consumed
an excessive amount of memory. With this update, the code releasing
the memory has been added and the problem no longer occurs.
(BZ#708516)

* Under certain circumstances, if services requiring Kerberos
authentication sent two authentication requests to the authenticating
server, the second authentication request was flagged as a replay
attack. As a result, the second authentication attempt was denied.
This update applies an upstream patch that fixes this bug. (BZ#713500)

* Previously, if Kerberos credentials had expired, the klist command
could terminate unexpectedly with a segmentation fault when invoked
with the -s option. This happened when klist encountered and failed to
process an entry with no realm name while scanning the credential
cache. With this update, the underlying code has been modified and the
command handles such entries correctly. (BZ#729067)

* Due to a regression, multi-line FTP macros terminated prematurely
with a segmentation fault. This occurred because the previously-added
patch failed to properly support multi-line macros. This update
restores the support for multi-line macros and the problem no longer
occurs. (BZ#735363, BZ#736132)

All users of krb5 are advised to upgrade to these updated packages,
which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002657.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"krb5-devel-1.6.1-70.el5")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-libs-1.6.1-70.el5")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-server-1.6.1-70.el5")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-server-ldap-1.6.1-70.el5")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-workstation-1.6.1-70.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-server-ldap / etc");
}
