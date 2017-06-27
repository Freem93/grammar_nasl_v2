#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:236. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12502);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2004-0523");
  script_osvdb_id(6846);
  script_xref(name:"RHSA", value:"2004:236");

  script_name(english:"RHEL 2.1 / 3 : krb5 (RHSA-2004:236)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Kerberos 5 (krb5) packages which correct buffer overflows in
the krb5_aname_to_localname function are now available.

Kerberos is a network authentication system.

Bugs have been fixed in the krb5_aname_to_localname library function.
Specifically, buffer overflows were possible for all Kerberos versions
up to and including 1.3.3. The krb5_aname_to_localname function
translates a Kerberos principal name to a local account name,
typically a UNIX username. This function is frequently used when
performing authorization checks.

If configured with mappings from particular Kerberos principals to
particular UNIX user names, certain functions called by
krb5_aname_to_localname will not properly check the lengths of buffers
used to store portions of the principal name. If configured to map
principals to user names using rules, krb5_aname_to_localname would
consistently write one byte past the end of a buffer allocated from
the heap. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0523 to this issue.

Only configurations which enable the explicit mapping or rules-based
mapping functionality of krb5_aname_to_localname() are vulnerable.
These configurations are not the default.

Users of Kerberos are advised to upgrade to these erratum packages
which contain backported security patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0523.html"
  );
  # http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2004-001-an_to_ln.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c54187f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-236.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:236";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-devel-1.2.2-27")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-libs-1.2.2-27")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-server-1.2.2-27")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"krb5-workstation-1.2.2-27")) flag++;

  if (rpm_check(release:"RHEL3", reference:"krb5-devel-1.2.7-24")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-libs-1.2.7-24")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-server-1.2.7-24")) flag++;
  if (rpm_check(release:"RHEL3", reference:"krb5-workstation-1.2.7-24")) flag++;

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
