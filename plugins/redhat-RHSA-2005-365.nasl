#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:365. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18019);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2005-0965", "CVE-2005-0966", "CVE-2005-0967");
  script_osvdb_id(15276, 15277, 15278, 15279, 15280);
  script_xref(name:"RHSA", value:"2005:365");

  script_name(english:"RHEL 3 / 4 : gaim (RHSA-2005:365)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gaim package that fixes multiple denial of service issues
is now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Gaim application is a multi-protocol instant messaging client.

A buffer overflow bug was found in the way gaim escapes HTML. It is
possible that a remote attacker could send a specially crafted message
to a Gaim client, causing it to crash. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0965
to this issue.

A bug was found in several of gaim's IRC processing functions. These
functions fail to properly remove various markup tags within an IRC
message. It is possible that a remote attacker could send a specially
crafted message to a Gaim client connected to an IRC server, causing
it to crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0966 to this issue.

A bug was found in gaim's Jabber message parser. It is possible for a
remote Jabber user to send a specially crafted message to a Gaim
client, causing it to crash. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0967 to this
issue.

In addition to these denial of service issues, multiple minor upstream
bugfixes are included in this update.

Users of Gaim are advised to upgrade to this updated package which
contains Gaim version 1.2.1 and is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0965.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0966.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0967.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/394806/2005-04-01/2005-04-07/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-365.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gaim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/01");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:365";
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
  if (rpm_check(release:"RHEL3", reference:"gaim-1.2.1-4.el3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gaim-1.2.1-4.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gaim");
  }
}
