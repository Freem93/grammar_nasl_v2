#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1439. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56743);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_bugtraq_id(50589, 50593, 50595);
  script_osvdb_id(76947, 76948, 76952);
  script_xref(name:"RHSA", value:"2011:1439");

  script_name(english:"RHEL 6 : thunderbird (RHSA-2011:1439)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A flaw was found in the way Thunderbird handled certain add-ons.
Malicious, remote content could cause an add-on to elevate its
privileges, which could lead to arbitrary code execution with the
privileges of the user running Thunderbird. (CVE-2011-3647)

A cross-site scripting (XSS) flaw was found in the way Thunderbird
handled certain multibyte character sets. Malicious, remote content
could cause Thunderbird to run JavaScript code with the permissions of
different remote content. (CVE-2011-3648)

A flaw was found in the way Thunderbird handled large JavaScript
scripts. Malicious, remote content could cause Thunderbird to crash
or, potentially, execute arbitrary code with the privileges of the
user running Thunderbird. (CVE-2011-3650)

All Thunderbird users should upgrade to this updated package, which
resolves these issues. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3648.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3650.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1439.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1439";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-3.1.16-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-3.1.16-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-3.1.16-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-debuginfo-3.1.16-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-debuginfo-3.1.16-2.el6_1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-debuginfo-3.1.16-2.el6_1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
  }
}
