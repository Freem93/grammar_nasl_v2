#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:038. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16160);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2004-1316");
  script_osvdb_id(12637);
  script_xref(name:"RHSA", value:"2005:038");

  script_name(english:"RHEL 2.1 / 3 : mozilla (RHSA-2005:038)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix a buffer overflow issue are now
available.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

iSEC Security Research has discovered a buffer overflow bug in the way
Mozilla handles NNTP URLs. If a user visits a malicious web page or is
convinced to click on a malicious link, it may be possible for an
attacker to execute arbitrary code on the victim's machine. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-1316 to this issue.

Users of Mozilla should upgrade to these updated packages, which
contain backported patches and are not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1316.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isec.pl/vulnerabilities/isec-0020-mozilla.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-038.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/29");
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
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:038";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-chat-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-devel-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-dom-inspector-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-js-debugger-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-mail-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-devel-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-1.4.3-2.1.5")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-devel-1.4.3-2.1.5")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mozilla-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-chat-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-devel-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-dom-inspector-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-js-debugger-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-mail-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-devel-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-1.4.3-3.0.7")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-devel-1.4.3-3.0.7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla / mozilla-chat / mozilla-devel / mozilla-dom-inspector / etc");
  }
}
