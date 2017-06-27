#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1762. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79291);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/17 20:10:04 $");

  script_cve_id("CVE-2014-3654");
  script_bugtraq_id(70951);
  script_xref(name:"RHSA", value:"2014:1762");

  script_name(english:"RHEL 5 / 6 : spacewalk-java (RHSA-2014:1762)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spacewalk-java packages that fix one security issue are now
available for Red Hat Satellite 5.5 and 5.6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat Satellite is a systems management tool for Linux-based
infrastructures. It allows for provisioning, monitoring, and remote
management of multiple Linux deployments with a single, centralized
tool. The spacewalk-java packages contain the code for the Java
version of the Spacewalk Website.

Stored and reflected cross-site scripting (XSS) flaws were found in
the way spacewalk-java displayed certain information. By sending a
specially crafted request to Satellite, a remote, authenticated
attacker could embed HTML content into the stored data, allowing them
to inject malicious content into the web page that is used to view
that data. (CVE-2014-3654)

Red Hat would like to thank Ron Bowes of Google for reporting this
issue.

All spacewalk-java users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1762.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
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

flag = 0;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-2.0.2-90.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-2.0.2-90.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-2.0.2-90.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-2.0.2-90.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-postgresql-2.0.2-90.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-2.0.2-90.el5sat")) flag++;

if (rpm_check(release:"RHEL6", reference:"spacewalk-java-2.0.2-90.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-2.0.2-90.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-2.0.2-90.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-2.0.2-90.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-java-postgresql-2.0.2-90.el6sat")) flag++;
if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-2.0.2-90.el6sat")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "spacewalk-java / spacewalk-java-config / spacewalk-java-lib / etc");
}
