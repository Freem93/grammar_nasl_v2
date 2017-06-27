#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1863. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79326);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2013-1854", "CVE-2013-1855", "CVE-2013-1857", "CVE-2013-4491", "CVE-2013-6414", "CVE-2013-6415", "CVE-2014-0130");
  script_osvdb_id(100524, 100525, 100528, 106704);
  script_xref(name:"RHSA", value:"2014:1863");

  script_name(english:"RHEL 6 : Subscription Asset Manager (RHSA-2014:1863)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Subscription Asset Manager 1.4 packages that fix multiple
security issues are now available.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Subscription Asset Manager acts as a proxy for handling
subscription information and software updates on client machines. Red
Hat Subscription Asset Manager is built on Ruby on Rails, a
model-view-controller (MVC) framework for web application development.
Action Pack implements the controller and the view components.

A directory traversal flaw was found in the way Ruby on Rails handled
wildcard segments in routes with implicit rendering. A remote attacker
could use this flaw to retrieve arbitrary local files accessible to a
Ruby on Rails application using the aforementioned routes via a
specially crafted request. (CVE-2014-0130)

A flaw was found in the way Ruby on Rails handled hashes in certain
queries. A remote attacker could use this flaw to perform a denial of
service (resource consumption) attack by sending specially crafted
queries that would result in the creation of Ruby symbols, which were
never garbage collected. (CVE-2013-1854)

Two cross-site scripting (XSS) flaws were found in Action Pack. A
remote attacker could use these flaws to conduct XSS attacks against
users of an application using Action Pack. (CVE-2013-1855,
CVE-2013-1857)

It was discovered that the internationalization component of Ruby on
Rails could, under certain circumstances, return a fallback HTML
string that contained user input. A remote attacker could possibly use
this flaw to perform a reflective cross-site scripting (XSS) attack by
providing a specially crafted input to an application using the
aforementioned component. (CVE-2013-4491)

A denial of service flaw was found in the header handling component of
Action View. A remote attacker could send strings in specially crafted
headers that would be cached indefinitely, which would result in all
available system memory eventually being consumed. (CVE-2013-6414)

It was found that the number_to_currency Action View helper did not
properly escape the unit parameter. An attacker could use this flaw to
perform a cross-site scripting (XSS) attack on an application that
uses data submitted by a user in the unit parameter. (CVE-2013-6415)

Red Hat would like to thank Ruby on Rails upstream for reporting these
issues. Upstream acknowledges Ben Murphy as the original reporter of
CVE-2013-1854, Charlie Somerville as the original reporter of
CVE-2013-1855, Alan Jenkins as the original reporter of CVE-2013-1857,
Peter McLarnan as the original reporter of CVE-2013-4491, Toby Hsieh
as the original reporter of CVE-2013-6414, and Ankit Gupta as the
original reporter of CVE-2013-6415.

All Subscription Asset Manager users are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1854.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1855.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1857.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6414.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0130.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1863.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-glue-candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-glue-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-headpin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-headpin-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activeresource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1863";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"candlepin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Subscription Asset Manager");

  if (rpm_check(release:"RHEL6", reference:"katello-common-1.4.3.28-1.el6sam_splice")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-glue-candlepin-1.4.3.28-1.el6sam_splice")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-glue-elasticsearch-1.4.3.28-1.el6sam_splice")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-headpin-1.4.3.28-1.el6sam_splice")) flag++;
  if (rpm_check(release:"RHEL6", reference:"katello-headpin-all-1.4.3.28-1.el6sam_splice")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-actionmailer-3.2.17-1.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-actionpack-3.2.17-6.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activemodel-3.2.17-1.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activerecord-3.2.17-5.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activeresource-3.2.17-1.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-activesupport-3.2.17-2.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-i18n-0.6.9-1.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-mail-2.5.4-1.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rack-1.4.5-3.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-rails-3.2.17-1.el6sam")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ruby193-rubygem-railties-3.2.17-1.el6sam")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "katello-common / katello-glue-candlepin / etc");
  }
}
