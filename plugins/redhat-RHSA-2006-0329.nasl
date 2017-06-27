#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0329. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21257);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:35:19 $");

  script_cve_id("CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_osvdb_id(24658, 24659, 24660, 24661, 24662, 24663, 24664, 24666, 24667, 24668, 24669, 24670, 24671, 24677, 24678, 24679, 24680);
  script_xref(name:"RHSA", value:"2006:0329");

  script_name(english:"RHEL 2.1 / 3 / 4 : mozilla (RHSA-2006:0329)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix several security bugs are now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 24 Apr 2006] The erratum text has been updated to include the
details of additional issues that were fixed by these erratum packages
but which were not public at the time of release. No changes have been
made to the packages.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several bugs were found in the way Mozilla processes malformed
JavaScript. A malicious web page could modify the content of a
different open web page, possibly stealing sensitive information or
conducting a cross-site scripting attack. (CVE-2006-1731,
CVE-2006-1732, CVE-2006-1741)

Several bugs were found in the way Mozilla processes certain
JavaScript actions. A malicious web page could execute arbitrary
JavaScript instructions with the permissions of 'chrome', allowing the
page to steal sensitive information or install browser malware.
(CVE-2006-1727, CVE-2006-1728, CVE-2006-1733, CVE-2006-1734,
CVE-2006-1735, CVE-2006-1742)

Several bugs were found in the way Mozilla processes malformed web
pages. A carefully crafted malicious web page could cause the
execution of arbitrary code as the user running Mozilla.
(CVE-2006-0748, CVE-2006-0749, CVE-2006-1730, CVE-2006-1737,
CVE-2006-1738, CVE-2006-1739, CVE-2006-1790)

A bug was found in the way Mozilla displays the secure site icon. If a
browser is configured to display the non-default secure site modal
warning dialog, it may be possible to trick a user into believing they
are viewing a secure site. (CVE-2006-1740)

A bug was found in the way Mozilla allows JavaScript mutation events
on 'input' form elements. A malicious web page could be created in
such a way that when a user submits a form, an arbitrary file could be
uploaded to the attacker. (CVE-2006-1729)

A bug was found in the way Mozilla executes in-line mail forwarding.
If a user can be tricked into forwarding a maliciously crafted mail
message as in-line content, it is possible for the message to execute
JavaScript with the permissions of 'chrome'. (CVE-2006-0884)

Users of Mozilla are advised to upgrade to these updated packages
containing Mozilla version 1.7.13 which corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0748.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0884.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1724.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1727.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1728.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1732.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1735.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1738.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1740.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1741.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1742.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1790.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0329.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:galeon");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2006:0329";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"galeon-1.2.14-1.2.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-chat-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-devel-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-dom-inspector-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-js-debugger-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-mail-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-devel-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-1.7.13-1.1.2.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-devel-1.7.13-1.1.2.2")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mozilla-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-chat-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-devel-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-dom-inspector-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-js-debugger-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-mail-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-devel-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-1.7.13-1.1.3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-devel-1.7.13-1.1.3.1")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-0.9.2-2.4.8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-0.9.2-2.4.8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-devel-0.9.2-2.4.8")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-devel-0.9.2-2.4.8")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-chat-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-devel-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-dom-inspector-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-js-debugger-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-mail-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nspr-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nspr-devel-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nss-1.7.13-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nss-devel-1.7.13-1.4.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / galeon / mozilla / mozilla-chat / etc");
  }
}
