#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0389. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25363);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/29 15:35:21 $");

  script_cve_id("CVE-2007-1995");
  script_bugtraq_id(23417);
  script_osvdb_id(34812);
  script_xref(name:"RHSA", value:"2007:0389");

  script_name(english:"RHEL 3 / 4 / 5 : quagga (RHSA-2007:0389)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated quagga package that fixes a security bug is now available
for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Quagga is a TCP/IP based routing software suite.

An out of bounds memory read flaw was discovered in Quagga's bgpd. A
configured peer of bgpd could cause Quagga to crash, leading to a
denial of service (CVE-2007-1995).

All users of Quagga should upgrade to this updated package, which
contains a backported patch to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0389.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected quagga, quagga-contrib and / or quagga-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0389";
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
  if (rpm_check(release:"RHEL3", reference:"quagga-0.96.2-12.3E")) flag++;


  if (rpm_check(release:"RHEL4", reference:"quagga-0.98.3-2.4.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"quagga-contrib-0.98.3-2.4.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"quagga-devel-0.98.3-2.4.0.1.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"quagga-0.98.6-2.1.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"quagga-0.98.6-2.1.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"quagga-0.98.6-2.1.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"quagga-contrib-0.98.6-2.1.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"quagga-contrib-0.98.6-2.1.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"quagga-contrib-0.98.6-2.1.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"quagga-devel-0.98.6-2.1.0.1.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-devel");
  }
}
