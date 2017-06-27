#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:330. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17659);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2005-0468", "CVE-2005-0469");
  script_osvdb_id(15093, 15094);
  script_xref(name:"RHSA", value:"2005:330");

  script_name(english:"RHEL 2.1 / 3 / 4 : krb5 (RHSA-2005:330)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages which fix two buffer overflow vulnerabilities in
the included Kerberos-aware telnet client are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Kerberos is a networked authentication system which uses a trusted
third party (a KDC) to authenticate clients and servers to each other.

The krb5-workstation package includes a Kerberos-aware telnet client.
Two buffer overflow flaws were discovered in the way the telnet client
handles messages from a server. An attacker may be able to execute
arbitrary code on a victim's machine if the victim can be tricked into
connecting to a malicious telnet server. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the names
CVE-2005-0468 and CVE-2005-0469 to these issues.

Users of krb5 should update to these erratum packages which contain a
backported patch to correct this issue.

Red Hat would like to thank iDEFENSE for their responsible disclosure
of this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0468.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0469.html"
  );
  # http://www.idefense.com/application/poi/display?id=220&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69f65c02"
  );
  # http://www.idefense.com/application/poi/display?id=221&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f2f4fd7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-330.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:330";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-devel-1.2.2-34")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-libs-1.2.2-34")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-server-1.2.2-34")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-workstation-1.2.2-34")) flag++;

  if (rpm_check(release:"RHEL3", reference:"krb5-devel-1.2.7-42")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-libs-1.2.7-42")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-server-1.2.7-42")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-workstation-1.2.7-42")) flag++;

  if (rpm_check(release:"RHEL4", reference:"krb5-devel-1.3.4-12")) flag++;
  if (rpm_check(release:"RHEL4", reference:"krb5-libs-1.3.4-12")) flag++;
  if (rpm_check(release:"RHEL4", reference:"krb5-server-1.3.4-12")) flag++;
  if (rpm_check(release:"RHEL4", reference:"krb5-workstation-1.3.4-12")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
  }
}
