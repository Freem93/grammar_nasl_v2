#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:766. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19713);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 18:06:54 $");

  script_cve_id("CVE-2004-2479", "CVE-2005-2794", "CVE-2005-2796");
  script_osvdb_id(12282, 19151, 19237);
  script_xref(name:"RHSA", value:"2005:766");

  script_name(english:"RHEL 2.1 / 3 / 4 : squid (RHSA-2005:766)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Squid package that fixes security issues is now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Squid is a full-featured Web proxy cache.

A bug was found in the way Squid displays error messages. A remote
attacker could submit a request containing an invalid hostname which
would result in Squid displaying a previously used error message. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-2479 to this issue.

Two denial of service bugs were found in the way Squid handles
malformed requests. A remote attacker could submit a specially crafted
request to Squid that would cause the server to crash. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2005-2794 and CVE-2005-2796 to these issues.

Please note that CVE-2005-2796 does not affect Red Hat Enterprise
Linux 2.1

Users of Squid should upgrade to this updated package that contains
backported patches, and is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-2479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2794.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2796.html"
  );
  # http://www.squid-cache.org/bugs/show_bug.cgi?id=1143
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.squid-cache.org/show_bug.cgi?id=1143"
  );
  # http://www.squid-cache.org/bugs/show_bug.cgi?id=1368
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.squid-cache.org/show_bug.cgi?id=1368"
  );
  # http://www.squid-cache.org/bugs/show_bug.cgi?id=1325
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.squid-cache.org/show_bug.cgi?id=1325"
  );
  # http://www.squid-cache.org/bugs/show_bug.cgi?id=1355
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.squid-cache.org/show_bug.cgi?id=1355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-766.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:766";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"squid-2.4.STABLE7-1.21as.10")) flag++;

  if (rpm_check(release:"RHEL3", reference:"squid-2.5.STABLE3-6.3E.14")) flag++;

  if (rpm_check(release:"RHEL4", reference:"squid-2.5.STABLE6-3.4E.11")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
  }
}
