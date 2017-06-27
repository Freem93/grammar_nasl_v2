#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0415. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79012);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2013-6393", "CVE-2014-2525");
  script_osvdb_id(105027);
  script_xref(name:"RHSA", value:"2014:0415");

  script_name(english:"RHEL 6 : libyaml (RHSA-2014:0415)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libyaml packages that fix two security issues are now
available for Red Hat Common for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

YAML is a data serialization format designed for human readability and
interaction with scripting languages. LibYAML is a YAML parser and
emitter written in C.

A buffer overflow flaw was found in the way the libyaml library parsed
URLs in YAML documents. An attacker able to load specially crafted
YAML input to an application using libyaml could cause the application
to crash or, potentially, execute arbitrary code with the privileges
of the user running the application. (CVE-2014-2525)

An integer overflow flaw was found in the way the libyaml library
handled excessively long YAML tags. An attacker able to load specially
crafted YAML input to application using libyaml could cause the
application to crash or, potentially, execute arbitrary code with the
privileges of the user running the application. (CVE-2013-6393)

Red Hat would like to thank oCERT for reporting the CVE-2014-2525
issue. oCERT acknowledges Ivan Fratric of the Google Security Team as
the original reporter. The CVE-2013-6393 issue was discovered by
Florian Weimer of the Red Hat Product Security Team.

Note: In their default configuration, applications distributed via the
Red Hat Common channel do not use the libyaml library for parsing
YAML, and are therefore not vulnerable to these issues.

All libyaml users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
applications linked against the libyaml library must be restarted for
this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6393.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0415.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libyaml, libyaml-debuginfo and / or libyaml-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libyaml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libyaml-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0415";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libyaml-0.1.3-1.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libyaml-0.1.3-1.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libyaml-debuginfo-0.1.3-1.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libyaml-debuginfo-0.1.3-1.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libyaml-devel-0.1.3-1.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libyaml-devel-0.1.3-1.4.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libyaml / libyaml-debuginfo / libyaml-devel");
  }
}
