#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1779. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71190);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-4566");
  script_osvdb_id(100516);
  script_xref(name:"RHSA", value:"2013:1779");

  script_name(english:"RHEL 5 / 6 : mod_nss (RHSA-2013:1779)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mod_nss package that fixes one security issue is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The mod_nss module provides strong cryptography for the Apache HTTP
Server via the Secure Sockets Layer (SSL) and Transport Layer Security
(TLS) protocols, using the Network Security Services (NSS) security
library.

A flaw was found in the way mod_nss handled the NSSVerifyClient
setting for the per-directory context. When configured to not require
a client certificate for the initial connection and only require it
for a specific directory, mod_nss failed to enforce this requirement
and allowed a client to access the directory when no valid client
certificate was provided. (CVE-2013-4566)

Red Hat would like to thank Albert Smith of OUSD(AT&L) for reporting
this issue.

All mod_nss users should upgrade to this updated package, which
contains a backported patch to correct this issue. The httpd service
must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1779.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_nss and / or mod_nss-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1779";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_nss-1.0.8-8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_nss-1.0.8-8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_nss-1.0.8-8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_nss-debuginfo-1.0.8-8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_nss-debuginfo-1.0.8-8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_nss-debuginfo-1.0.8-8.el5_10")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_nss-1.0.8-19.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_nss-1.0.8-19.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_nss-1.0.8-19.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_nss-debuginfo-1.0.8-19.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_nss-debuginfo-1.0.8-19.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_nss-debuginfo-1.0.8-19.el6_5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_nss / mod_nss-debuginfo");
  }
}
