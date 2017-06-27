#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0206 and 
# Oracle Linux Security Advisory ELSA-2014-0206 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72677);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2013-4449");
  script_bugtraq_id(63190);
  script_osvdb_id(98656);
  script_xref(name:"RHSA", value:"2014:0206");

  script_name(english:"Oracle Linux 5 : openldap (ELSA-2014-0206)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0206 :

Updated openldap packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols used to access and maintain distributed directory
information services over an IP network. The openldap package contains
configuration files, libraries, and documentation for OpenLDAP.

A denial of service flaw was found in the way the OpenLDAP server
daemon (slapd) performed reference counting when using the rwm
(rewrite/remap) overlay. A remote attacker able to query the OpenLDAP
server could use this flaw to crash the server by immediately
unbinding from the server after sending a search request.
(CVE-2013-4449)

Red Hat would like to thank Michael Vishchers from Seven Principles AG
for reporting this issue.

All openldap users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-February/003991.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers-overlays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL5", reference:"compat-openldap-2.3.43_2.2.29-27.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-2.3.43-27.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-clients-2.3.43-27.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-devel-2.3.43-27.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-servers-2.3.43-27.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-servers-overlays-2.3.43-27.el5_10")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-servers-sql-2.3.43-27.el5_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-devel / etc");
}
