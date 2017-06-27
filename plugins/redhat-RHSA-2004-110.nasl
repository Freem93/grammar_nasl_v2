#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:110. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12478);
  script_version ("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2003-0564", "CVE-2003-0594", "CVE-2004-0191");
  script_osvdb_id(4062);
  script_xref(name:"RHSA", value:"2004:110");

  script_name(english:"RHEL 2.1 / 3 : mozilla (RHSA-2004:110)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Mozilla packages that fix vulnerabilities in S/MIME parsing as
well as other issues and bugs are now available.

Mozilla is a Web browser and mail reader, designed for standards
compliance, performance and portability. Network Security Services
(NSS) is a set of libraries designed to support cross-platform
development of security-enabled server applications.

NISCC testing of implementations of the S/MIME protocol uncovered a
number of bugs in NSS versions prior to 3.9. The parsing of unexpected
ASN.1 constructs within S/MIME data could cause Mozilla to crash or
consume large amounts of memory. A remote attacker could potentially
trigger these bugs by sending a carefully-crafted S/MIME message to a
victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0564 to this issue.

Andreas Sandblad discovered a cross-site scripting issue that affects
various versions of Mozilla. When linking to a new page it is still
possible to interact with the old page before the new page has been
successfully loaded. Any JavaScript events will be invoked in the
context of the new page, making cross-site scripting possible if the
different pages belong to different domains. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0191 to this issue.

Flaws have been found in the cookie path handling between a number of
Web browsers and servers. The HTTP cookie standard allows a Web server
supplying a cookie to a client to specify a subset of URLs on the
origin server to which the cookie applies. Web servers such as Apache
do not filter returned cookies and assume that the client will only
send back cookies for requests that fall within the server-supplied
subset of URLs. However, by supplying URLs that use path traversal
(/../) and character encoding, it is possible to fool many browsers
into sending a cookie to a path outside of the originally-specified
subset. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0594 to this issue.

Users of Mozilla are advised to upgrade to these updated packages,
which contain Mozilla version 1.4.2 and are not vulnerable to these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0564.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0594.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/pki/nss/#NSS_39"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=227417"
  );
  # http://www.niscc.gov.uk/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cpni.gov.uk/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-110.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2004:110";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"galeon-1.2.13-0.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-chat-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-devel-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-dom-inspector-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-js-debugger-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-mail-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-devel-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-1.4.2-2.1.0")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-devel-1.4.2-2.1.0")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mozilla-1.4.2-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-chat-1.4.2-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-dom-inspector-1.4.2-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-js-debugger-1.4.2-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-mail-1.4.2-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-1.4.2-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-devel-1.4.2-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-1.4.2-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-devel-1.4.2-3.0.2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "galeon / mozilla / mozilla-chat / mozilla-devel / etc");
  }
}
