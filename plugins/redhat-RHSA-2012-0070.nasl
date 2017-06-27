#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0070. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57747);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:04:20 $");

  script_cve_id("CVE-2011-3009", "CVE-2011-4815");
  script_bugtraq_id(49126, 51198);
  script_osvdb_id(74841, 78118);
  script_xref(name:"RHSA", value:"2012:0070");

  script_name(english:"RHEL 4 / 5 : ruby (RHSA-2012:0070)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix two security issues are now available
for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A denial of service flaw was found in the implementation of
associative arrays (hashes) in Ruby. An attacker able to supply a
large number of inputs to a Ruby application (such as HTTP POST
request parameters sent to a web application) that are used as keys
when inserting data into an array could trigger multiple hash function
collisions, making array operations take an excessive amount of CPU
time. To mitigate this issue, randomization has been added to the hash
function to reduce the chance of an attacker successfully causing
intentional collisions. (CVE-2011-4815)

It was found that Ruby did not reinitialize the PRNG (pseudorandom
number generator) after forking a child process. This could eventually
lead to the PRNG returning the same result twice. An attacker keeping
track of the values returned by one child process could use this flaw
to predict the values the PRNG would return in other child processes
(as long as the parent process persisted). (CVE-2011-3009)

Red Hat would like to thank oCERT for reporting CVE-2011-4815. oCERT
acknowledges Julian Walde and Alexander Klink as the original
reporters of CVE-2011-4815.

All users of ruby are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ocert.org/advisories/ocert-2011-003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0070.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:0070";
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
  if (rpm_check(release:"RHEL4", reference:"irb-1.8.1-18.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"ruby-1.8.1-18.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"ruby-devel-1.8.1-18.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"ruby-docs-1.8.1-18.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"ruby-libs-1.8.1-18.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"ruby-mode-1.8.1-18.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"ruby-tcltk-1.8.1-18.el4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ruby-devel-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-docs-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-docs-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-docs-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-irb-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-irb-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-irb-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ruby-libs-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-mode-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-mode-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-mode-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-rdoc-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-rdoc-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-rdoc-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-ri-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-ri-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-ri-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-tcltk-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-tcltk-1.8.5-22.el5_7.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-tcltk-1.8.5-22.el5_7.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-irb / ruby-libs / etc");
  }
}
