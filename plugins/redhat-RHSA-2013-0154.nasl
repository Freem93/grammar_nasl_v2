#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0154. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64076);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-2660", "CVE-2012-2661", "CVE-2012-2694", "CVE-2012-2695", "CVE-2012-3424", "CVE-2012-3463", "CVE-2012-3464", "CVE-2012-3465", "CVE-2012-6496", "CVE-2013-0155", "CVE-2013-0156");
  script_osvdb_id(82403, 82610, 84243, 84513, 84515, 84516, 88661, 89025, 89026);
  script_xref(name:"RHSA", value:"2013:0154");

  script_name(english:"RHEL 6 : Ruby on Rails in Subscription Asset Manager (RHSA-2013:0154)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rubygem-actionpack, rubygem-activesupport, and
rubygem-activerecord packages that fix multiple security issues are
now available for Red Hat Subscription Asset Manager.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ruby on Rails is a model-view-controller (MVC) framework for web
application development. Action Pack implements the controller and the
view components. Active Record implements object-relational mapping
for accessing database entries using objects. Active Support provides
support and utility classes used by the Ruby on Rails framework.

Multiple flaws were found in the way Ruby on Rails performed XML
parameter parsing in HTTP requests. A remote attacker could use these
flaws to execute arbitrary code with the privileges of a Ruby on Rails
application, perform SQL injection attacks, or bypass the
authentication using a specially-created HTTP request. (CVE-2013-0156)

Red Hat is aware that a public exploit for the CVE-2013-0156 issues is
available that allows remote code execution in applications using Ruby
on Rails.

Multiple input validation vulnerabilities were discovered in
rubygem-activerecord. A remote attacker could possibly use these flaws
to perform a SQL injection attack against an application using
rubygem-activerecord. (CVE-2012-2661, CVE-2012-2695, CVE-2012-6496,
CVE-2013-0155)

Multiple input validation vulnerabilities were discovered in
rubygem-actionpack. A remote attacker could possibly use these flaws
to perform a SQL injection attack against an application using
rubygem-actionpack and rubygem-activerecord. (CVE-2012-2660,
CVE-2012-2694)

Multiple cross-site scripting (XSS) flaws were found in
rubygem-actionpack. A remote attacker could use these flaws to conduct
XSS attacks against users of an application using rubygem-actionpack.
(CVE-2012-3463, CVE-2012-3464, CVE-2012-3465)

A flaw was found in the HTTP digest authentication implementation in
rubygem-actionpack. A remote attacker could use this flaw to cause a
denial of service of an application using rubygem-actionpack and
digest authentication. (CVE-2012-3424)

Users are advised to upgrade to these updated rubygem-actionpack,
rubygem-activesupport, and rubygem-activerecord packages, which
resolve these issues. Katello must be restarted ('service katello
restart') for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2660.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2661.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2694.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2695.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3464.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3465.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6496.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0155.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/solutions/290903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0154.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected rubygem-actionpack, rubygem-activerecord and / or
rubygem-activesupport packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails XML Processor YAML Deserialization Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0154";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"candlepin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Subscription Asset Manager");

  if (rpm_check(release:"RHEL6", reference:"rubygem-actionpack-3.0.10-11.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-activerecord-3.0.10-8.el6cf")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-activesupport-3.0.10-5.el6cf")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-actionpack / rubygem-activerecord / rubygem-activesupport");
  }
}
