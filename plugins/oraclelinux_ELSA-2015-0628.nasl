#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0628 and 
# Oracle Linux Security Advisory ELSA-2015-0628 respectively.
#

include("compat.inc");

if (description)
{
  script_id(81660);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 16:04:32 $");

  script_cve_id("CVE-2014-8105");
  script_bugtraq_id(72985);
  script_xref(name:"RHSA", value:"2015:0628");

  script_name(english:"Oracle Linux 6 : 389-ds-base (ELSA-2015-0628)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0628 :

Updated 389-ds-base packages that fix one security issue, two bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

An information disclosure flaw was found in the way the 389 Directory
Server stored information in the Changelog that is exposed via the
'cn=changelog' LDAP sub-tree. An unauthenticated user could in certain
cases use this flaw to read data from the Changelog, which could
include sensitive information such as plain-text passwords.
(CVE-2014-8105)

This issue was discovered by Petr Spacek of the Red Hat Identity
Management Engineering Team.

This update also fixes the following bugs :

* In multi-master replication (MMR), deleting a single-valued
attribute of a Directory Server (DS) entry was previously in some
cases not correctly replicated. Consequently, the entry state in the
replica systems did not reflect the intended changes. This bug has
been fixed and the removal of a single-valued attribute is now
properly replicated. (BZ#1179099)

* Prior to this update, the Directory Server (DS) always checked the
ACI syntax. As a consequence, removing an ACI failed with a syntax
error. With this update, the ACI check is stopped when the ACI is
going to be removed, and the removal thus works as expected.
(BZ#1179100)

In addition, this update adds the following enhancement :

* The buffer size limit for the 389-ds-base application has been
increased to 2MB in order to match the buffer size limit of Simple
Authentication and Security Layer (SASL) and Basic Encoding Rules
(BER). (BZ#1179595)

All 389-ds-base users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement. After installing this update, the 389 server
service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004869.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"389-ds-base-1.2.11.15-50.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"389-ds-base-devel-1.2.11.15-50.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"389-ds-base-libs-1.2.11.15-50.el6_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs");
}
