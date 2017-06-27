#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0077. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24707);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/29 15:35:20 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1092", "CVE-2007-1282");
  script_bugtraq_id(21240, 22396, 22566, 22679, 22694, 22826);
  script_osvdb_id(30641, 32104, 32105, 32106, 32107, 32108, 32109, 32110, 32111, 32112, 32114, 32115, 33812, 79165);
  script_xref(name:"RHSA", value:"2007:0077");

  script_name(english:"RHEL 2.1 / 3 / 4 : seamonkey (RHSA-2007:0077)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security bugs are now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 26 February 2007] Packages for Red Hat Enterprise Linux 4
have been updated to correct an issue which prevented Evolution and
other applications linked against the NSS library from functioning.

[Updated 12 March 2007] Packages for Red Hat Enterprise Linux 2.1 and
3 have been updated to correct an issue which prevented Evolution and
other applications linked against the NSS library from functioning.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several flaws were found in the way SeaMonkey processed certain
malformed JavaScript code. A malicious web page could execute
JavaScript code in such a way that may result in SeaMonkey crashing or
executing arbitrary code as the user running SeaMonkey.
(CVE-2007-0775, CVE-2007-0777)

Several cross-site scripting (XSS) flaws were found in the way
SeaMonkey processed certain malformed web pages. A malicious web page
could display misleading information which may result in a user
unknowingly divulging sensitive information such as a password.
(CVE-2006-6077, CVE-2007-0995, CVE-2007-0996)

A flaw was found in the way SeaMonkey cached web pages on the local
disk. A malicious web page may be able to inject arbitrary HTML into a
browsing session if the user reloads a targeted site. (CVE-2007-0778)

A flaw was found in the way SeaMonkey displayed certain web content. A
malicious web page could generate content which could overlay user
interface elements such as the hostname and security indicators,
tricking a user into thinking they are visiting a different site.
(CVE-2007-0779)

Two flaws were found in the way SeaMonkey displayed blocked popup
windows. If a user can be convinced to open a blocked popup, it is
possible to read arbitrary local files, or conduct an XSS attack
against the user. (CVE-2007-0780, CVE-2007-0800)

Two buffer overflow flaws were found in the Network Security Services
(NSS) code for processing the SSLv2 protocol. Connecting to a
malicious secure web server could cause the execution of arbitrary
code as the user running SeaMonkey. (CVE-2007-0008, CVE-2007-0009)

A flaw was found in the way SeaMonkey handled the 'location.hostname'
value during certain browser domain checks. This flaw could allow a
malicious web site to set domain cookies for an arbitrary site, or
possibly perform an XSS attack. (CVE-2007-0981)

Users of SeaMonkey are advised to upgrade to these erratum packages,
which contain SeaMonkey version 1.0.8 that corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-6077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0778.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0779.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0994.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0996.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1282.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0077.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2007:0077";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-chat-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-devel-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-dom-inspector-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-js-debugger-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-mail-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nspr-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nspr-devel-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nss-1.0.8-0.2.el2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"seamonkey-nss-devel-1.0.8-0.2.el2")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-chat-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-devel-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-dom-inspector-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-js-debugger-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-mail-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-devel-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-1.0.8-0.2.el3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-devel-1.0.8-0.2.el3")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-0.10-0.7.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-0.10-0.7.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-devel-0.10-0.7.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-devel-0.10-0.7.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-chat-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-devel-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-dom-inspector-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-js-debugger-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-mail-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-nspr-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-nspr-devel-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-nss-1.0.8-0.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"seamonkey-nss-devel-1.0.8-0.2.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / seamonkey / seamonkey-chat / etc");
  }
}
