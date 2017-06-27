#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0975. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55642);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2010-4341");
  script_bugtraq_id(45961);
  script_xref(name:"RHSA", value:"2011:0975");

  script_name(english:"RHEL 5 : sssd (RHSA-2011:0975)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix one security issue, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The System Security Services Daemon (SSSD) provides a set of daemons
to manage access to remote directories and authentication mechanisms.
It provides an NSS and PAM interface toward the system and a pluggable
back-end system to connect to multiple different account sources. It
is also the basis to provide client auditing and policy services for
projects such as FreeIPA.

A flaw was found in the SSSD PAM responder that could allow a local
attacker to force SSSD to enter an infinite loop via a
carefully-crafted packet. With SSSD unresponsive, legitimate users
could be denied the ability to log in to the system. (CVE-2010-4341)

Red Hat would like to thank Sebastian Krahmer for reporting this
issue.

These updated sssd packages include a number of bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Refer to the Red Hat Enterprise Linux 5.7 Technical Notes
for information about these changes :

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/
5.7_Technical_Notes/sssd.html#RHSA-2011-0975

All sssd users are advised to upgrade to these updated sssd packages,
which upgrade SSSD to upstream version 1.5.1 to correct this issue,
and fix the bugs and add the enhancements noted in the Technical
Notes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4341.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedorahosted.org/sssd/wiki/Releases/Notes-1.5.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0975.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sssd, sssd-client and / or sssd-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0975";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sssd-1.5.1-37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sssd-1.5.1-37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sssd-1.5.1-37.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"sssd-client-1.5.1-37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sssd-tools-1.5.1-37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sssd-tools-1.5.1-37.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sssd-tools-1.5.1-37.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd / sssd-client / sssd-tools");
  }
}
