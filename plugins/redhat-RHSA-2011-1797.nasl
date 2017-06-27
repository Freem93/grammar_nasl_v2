#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1797. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57053);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 16:12:17 $");

  script_cve_id("CVE-2010-2761", "CVE-2010-4410", "CVE-2011-3597");
  script_bugtraq_id(44199, 45145, 49911);
  script_osvdb_id(69588, 69589, 75990);
  script_xref(name:"RHSA", value:"2011:1797");

  script_name(english:"RHEL 4 / 5 : perl (RHSA-2011:1797)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated perl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Perl is a high-level programming language commonly used for system
administration utilities and web programming.

It was found that the 'new' constructor of the Digest module used its
argument as part of the string expression passed to the eval()
function. An attacker could possibly use this flaw to execute
arbitrary Perl code with the privileges of a Perl program that uses
untrusted input as an argument to the constructor. (CVE-2011-3597)

It was found that the Perl CGI module used a hard-coded value for the
MIME boundary string in multipart/x-mixed-replace content. A remote
attacker could possibly use this flaw to conduct an HTTP response
splitting attack via a specially crafted HTTP request. (CVE-2010-2761)

A CRLF injection flaw was found in the way the Perl CGI module
processed a sequence of non-whitespace preceded by newline characters
in the header. A remote attacker could use this flaw to conduct an
HTTP response splitting attack via a specially crafted sequence of
characters provided to the CGI module. (CVE-2010-4410)

All Perl users should upgrade to these updated packages, which contain
backported patches to correct these issues. All running Perl programs
must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2761.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4410.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1797.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl and / or perl-suidperl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/09");
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
  rhsa = "RHSA-2011:1797";
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
  if (rpm_check(release:"RHEL4", reference:"perl-5.8.5-57.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"perl-suidperl-5.8.5-57.el4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"perl-5.8.8-32.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"perl-5.8.8-32.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"perl-5.8.8-32.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"perl-suidperl-5.8.8-32.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"perl-suidperl-5.8.8-32.el5_7.6")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"perl-suidperl-5.8.8-32.el5_7.6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-suidperl");
  }
}
