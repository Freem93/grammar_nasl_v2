#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0153. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51562);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2010-4345");
  script_bugtraq_id(45341);
  script_xref(name:"RHSA", value:"2011:0153");

  script_name(english:"RHEL 4 / 5 : exim (RHSA-2011:0153)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated exim packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Exim is a mail transport agent (MTA) developed at the University of
Cambridge for use on UNIX systems connected to the Internet.

A privilege escalation flaw was discovered in Exim. If an attacker
were able to gain access to the 'exim' user, they could cause Exim to
execute arbitrary commands as the root user. (CVE-2010-4345)

This update adds a new configuration file,
'/etc/exim/trusted-configs'. To prevent Exim from running arbitrary
commands as root, Exim will now drop privileges when run with a
configuration file not listed as trusted. This could break backwards
compatibility with some Exim configurations, as the trusted-configs
file only trusts '/etc/exim/exim.conf' and '/etc/exim/exim4.conf' by
default. If you are using a configuration file not listed in the new
trusted-configs file, you will need to add it manually.

Additionally, Exim will no longer allow a user to execute exim as root
with the -D command line option to override macro definitions. All
macro definitions that require root permissions must now reside in a
trusted configuration file.

Users of Exim are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing
this update, the exim daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0153.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exim-sa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0153";
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
  if (rpm_check(release:"RHEL4", reference:"exim-4.43-1.RHEL4.5.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.3")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"exim-4.63-5.el5_6.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"exim-4.63-5.el5_6.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"exim-4.63-5.el5_6.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"exim-mon-4.63-5.el5_6.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"exim-mon-4.63-5.el5_6.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"exim-mon-4.63-5.el5_6.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"exim-sa-4.63-5.el5_6.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"exim-sa-4.63-5.el5_6.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"exim-sa-4.63-5.el5_6.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-doc / exim-mon / exim-sa");
  }
}
