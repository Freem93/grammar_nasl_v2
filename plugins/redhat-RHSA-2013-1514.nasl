#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1514. The text
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70871);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/09 19:10:17 $");

  script_cve_id("CVE-2013-4480");
  script_bugtraq_id(63694);
  script_osvdb_id(99691);
  script_xref(name:"RHSA", value:"2013:1514");

  script_name(english:"RHEL 5 / 6 : spacewalk-java in Satellite Server (RHSA-2013:1514)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated spacewalk-java packages that fix one security issue are now
available for Red Hat Satellite 5.3, 5.4, 5.5 and 5.6.

The Red Hat Security Response Team has rated this update as having a
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Satellite is a systems management tool for Linux-based
infrastructures. It allows for provisioning, monitoring, and remote
management of multiple Linux deployments with a single, centralized
tool. The spacewalk-java packages contain the code for the Java
version of the Spacewalk Website.

It was found that the web interface provided by Red Hat Satellite to
create the initial administrator user was not disabled after the
initial user was created. A remote attacker could use this flaw to
create an administrator user with credentials they specify. This user
could then be used to assume control of the Satellite server.
(CVE-2013-4480)

This issue was discovered by Andrew Spurrier of Red Hat.

All spacewalk-java users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-4480.html");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2013-1514.html");
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;

if (! (rpm_exists(release:"RHEL5", rpm:"spacewalk-java-") || rpm_exists(release:"RHEL6", rpm:"spacewalk-java-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

# Red Hat Network Satellite (v. 5.4 for RHEL 5/6), spacewalk-java-1.2
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-1.7.0-0.el5sat") || rpm_check(release:"RHEL6", reference:"spacewalk-java-1.7.0-0.el6sat"))
{
  # Clear existing test list and report
  __pkg_tests = make_list();
  __rpm_report = '';
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-1.2.39-135.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-1.2.39-135.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-1.2.39-135.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-1.2.39-135.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-1.2.39-135.el5sat")) flag++;

  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-1.2.39-135.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-1.2.39-135.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-1.2.39-135.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-1.2.39-135.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-1.2.39-135.el6sat")) flag++;
}

# Red Hat Network Satellite (v. 5.5 for RHEL 5/6), spacewalk-java-1.7
else
{
  # Clear existing test list and report
  __pkg_tests = make_list();
  __rpm_report = '';
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-1.7.54-121.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-1.7.54-121.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-1.7.54-121.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-1.7.54-121.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-1.7.54-121.el5sat")) flag++;

  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-1.7.54-121.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-1.7.54-121.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-1.7.54-121.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-1.7.54-121.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-1.7.54-121.el6sat")) flag++;
}

# Red Hat Network Satellite (v. 5.3 for RHEL 5), spacewalk-java-0.5
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-0.5.44-97.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-0.5.44-97.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-0.5.44-97.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-0.5.44-97.el5sat")) flag++;

# Red Hat Network Satellite (v. 5.6 for RHEL 5/6), spacewalk-java-2.0
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-2.0.2-48.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-2.0.2-48.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-2.0.2-48.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-2.0.2-48.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-postgresql-2.0.2-48.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-2.0.2-48.el5sat")) flag++;

if (rpm_check(release:"RHEL6", reference:"spacewalk-java-2.0.2-48.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-2.0.2-48.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-2.0.2-48.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-2.0.2-48.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-postgresql-2.0.2-48.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-2.0.2-48.el6sat")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "Satellite Server");
