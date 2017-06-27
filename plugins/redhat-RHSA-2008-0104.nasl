#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0104. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30246);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/03 17:16:32 $");

  script_cve_id("CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593");
  script_bugtraq_id(24293, 27406, 27683);
  script_xref(name:"RHSA", value:"2008:0104");

  script_name(english:"RHEL 2.1 / 3 / 4 : seamonkey (RHSA-2008:0104)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security issues are now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several flaws were found in the way SeaMonkey processed certain
malformed web content. A webpage containing malicious content could
cause SeaMonkey to crash, or potentially execute arbitrary code as the
user running SeaMonkey. (CVE-2008-0412, CVE-2008-0413, CVE-2008-0415,
CVE-2008-0419)

Several flaws were found in the way SeaMonkey displayed malformed web
content. A webpage containing specially crafted content could trick a
user into surrendering sensitive information. (CVE-2008-0591,
CVE-2008-0593)

A flaw was found in the way SeaMonkey stored password data. If a user
saves login information for a malicious website, it could be possible
to corrupt the password database, preventing the user from properly
accessing saved password data. (CVE-2008-0417)

A flaw was found in the way SeaMonkey handles certain chrome URLs. If
a user has certain extensions installed, it could allow a malicious
website to steal sensitive session data. Note: this flaw does not
affect a default installation of SeaMonkey. (CVE-2008-0418)

A flaw was found in the way SeaMonkey saves certain text files. If a
website offers a file of type 'plain/text', rather than 'text/plain',
SeaMonkey will not show future 'text/plain' content to the user in the
browser, forcing them to save those files locally to view the content.
(CVE-2008-0592)

Users of SeaMonkey are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0304.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0413.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0416.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0592.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0104.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 94, 119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2008:0104";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-chat-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-devel-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-js-debugger-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-mail-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nspr-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nss-1.0.9-0.9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nss-devel-1.0.9-0.9.el2")) flag++;


  if (rpm_check(release:"RHEL3", reference:"seamonkey-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-chat-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-devel-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-dom-inspector-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-js-debugger-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-mail-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-devel-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-1.0.9-0.9.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-devel-1.0.9-0.9.el3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"seamonkey-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-chat-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-devel-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-dom-inspector-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-js-debugger-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-mail-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-nspr-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-nspr-devel-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-nss-1.0.9-9.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-nss-devel-1.0.9-9.el4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey / seamonkey-chat / seamonkey-devel / etc");
  }
}
