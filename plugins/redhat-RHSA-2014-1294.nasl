#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1294. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79051);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/09 22:38:11 $");

  script_cve_id("CVE-2014-6271");
  script_osvdb_id(112004);
  script_xref(name:"RHSA", value:"2014:1294");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"RHEL 5 / 6 : bash (RHSA-2014:1294) (Shellshock)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bash packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 Extended Life Cycle Support, Red Hat
Enterprise Linux 5.6 Long Life, Red Hat Enterprise Linux 5.9 Extended
Update Support, Red Hat Enterprise Linux 6.2 Advanced Update Support,
and Red Hat Enterprise Linux 6.4 Extended Update Support.

Red Hat Product Security has rated this update as having Critical
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The GNU Bourne Again shell (Bash) is a shell and command language
interpreter compatible with the Bourne shell (sh). Bash is the default
shell for Red Hat Enterprise Linux.

A flaw was found in the way Bash evaluated certain specially crafted
environment variables. An attacker could use this flaw to override or
bypass environment restrictions to execute shell commands. Certain
services and applications allow remote unauthenticated attackers to
provide environment variables, allowing them to exploit this issue.
(CVE-2014-6271)

For additional information on the CVE-2014-6271 flaw, refer to the
Knowledgebase article at https://access.redhat.com/articles/1200223

Red Hat would like to thank Stephane Chazelas for reporting this
issue.

All bash users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6271.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/1200223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1294.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bash, bash-debuginfo and / or bash-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.6|5\.9|6\.2|6\.4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.6 / 5.9 / 6.2 / 6.4", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1294";
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"bash-3.2-24.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"bash-3.2-32.el5_9.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"bash-3.2-32.el5_9.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"bash-3.2-24.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"bash-3.2-32.el5_9.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"bash-debuginfo-3.2-24.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"bash-debuginfo-3.2-32.el5_9.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"bash-debuginfo-3.2-32.el5_9.2")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"bash-debuginfo-3.2-24.el5_6.1")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"bash-debuginfo-3.2-32.el5_9.2")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bash-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"bash-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bash-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"bash-4.1.2-9.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bash-debuginfo-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"bash-debuginfo-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bash-debuginfo-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"bash-debuginfo-4.1.2-9.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"bash-doc-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"bash-doc-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"bash-doc-4.1.2-15.el6_4.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"bash-doc-4.1.2-9.el6_2.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash / bash-debuginfo / bash-doc");
  }
}
