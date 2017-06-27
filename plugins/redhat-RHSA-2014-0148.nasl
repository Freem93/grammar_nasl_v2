#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0148. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78995);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:40:56 $");

  script_cve_id("CVE-2012-6149", "CVE-2013-1869", "CVE-2013-1871", "CVE-2013-4415");
  script_bugtraq_id(65590, 65592, 65593, 65594);
  script_xref(name:"RHSA", value:"2014:0148");

  script_name(english:"RHEL 5 / 6 : spacewalk-java, spacewalk-web and satellite-branding (RHSA-2014:0148)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spacewalk-java, spacewalk-web, and satellite-branding packages
that fix multiple security issues are now available for Red Hat
Satellite 5.6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Satellite is a systems management tool for Linux-based
infrastructures. It allows for provisioning, remote management and
monitoring of multiple Linux deployments with a single, centralized
tool.

A cross-site scripting (XSS) flaw was found in the way the Red Hat
Satellite web interface performed sanitization of notes for registered
systems. A remote authenticated Red Hat Satellite user could create a
malicious note that, when viewed by a victim, could execute arbitrary
web script with the privileges of the user viewing that note.
(CVE-2012-6149)

Multiple cross-site scripting (XSS) flaws were found in the Red Hat
Satellite web interface. A remote attacker could provide a specially
crafted link that, when visited by an authenticated Red Hat Satellite
user, would lead to arbitrary web script execution in the context of
the user's web interface session. (CVE-2013-1871, CVE-2013-4415)

An HTTP header injection flaw was found in the way the Red Hat
Satellite web interface processed the return URL parameter for all
HTTP GET requests. A remote attacker could use this flaw to conduct
cross-site scripting (XSS) and HTTP response splitting attacks against
users visiting the site. (CVE-2013-1869)

Red Hat would like to thank Ben Ford of Puppet Labs for reporting
CVE-2012-6149, Ryan Giobbi of UPMC for reporting CVE-2013-1869 and
CVE-2013-1871, and Adam Willard and Jose Carlos de Arriba of
Foreground Security for reporting CVE-2013-4415.

Users of Red Hat Satellite 5.6 are advised to upgrade to these updated
packages, which resolve these issues. For this update to take effect,
Red Hat Satellite must be restarted. Refer to the Solution section for
details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6149.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1869.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0148.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-branding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-base-minimal-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-dobby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-grail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-pxt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-sniglets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0148";
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
  if (rpm_check(release:"RHEL5", reference:"satellite-branding-5.6.0.23-1.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-base-2.0.3-19.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-base-minimal-2.0.3-19.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-base-minimal-config-2.0.3-19.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-dobby-2.0.3-19.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-grail-2.0.3-19.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-html-2.0.3-19.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-2.0.2-58.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-2.0.2-58.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-2.0.2-58.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-2.0.2-58.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-postgresql-2.0.2-58.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-pxt-2.0.3-19.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-sniglets-2.0.3-19.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-2.0.2-58.el5sat")) flag++;

  if (rpm_check(release:"RHEL6", reference:"satellite-branding-5.6.0.23-1.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-base-2.0.3-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-base-minimal-2.0.3-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-base-minimal-config-2.0.3-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-dobby-2.0.3-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-grail-2.0.3-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-html-2.0.3-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-2.0.2-58.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-2.0.2-58.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-2.0.2-58.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-2.0.2-58.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-postgresql-2.0.2-58.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-pxt-2.0.3-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-sniglets-2.0.3-19.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-2.0.2-58.el6sat")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "satellite-branding / spacewalk-base / spacewalk-base-minimal / etc");
  }
}
