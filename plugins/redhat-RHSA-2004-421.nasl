#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:421. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14214);
  script_version ("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/28 17:44:45 $");

  script_cve_id("CVE-2004-0597", "CVE-2004-0599", "CVE-2004-0718", "CVE-2004-0722", "CVE-2004-0757", "CVE-2004-0758", "CVE-2004-0759", "CVE-2004-0760", "CVE-2004-0761", "CVE-2004-0762", "CVE-2004-0763", "CVE-2004-0764", "CVE-2004-0765");
  script_osvdb_id(7466, 7939, 8281, 8303, 8304, 8305, 8307, 8308, 8309, 8310, 8311, 8312, 8313, 8314, 8315, 8316, 59316);
  script_xref(name:"RHSA", value:"2004:421");

  script_name(english:"RHEL 2.1 / 3 : mozilla (RHSA-2004:421)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages based on version 1.4.3 that fix a number of
security issues for Red Hat Enterprise Linux are now available.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

A number of flaws have been found in Mozilla 1.4 that have been fixed
in the Mozilla 1.4.3 release :

Zen Parse reported improper input validation to the SOAPParameter
object constructor leading to an integer overflow and controllable
heap corruption. Malicious JavaScript could be written to utilize this
flaw and could allow arbitrary code execution. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0722 to this issue.

During a source code audit, Chris Evans discovered a buffer overflow
and integer overflows which affect the libpng code inside Mozilla. An
attacker could create a carefully crafted PNG file in such a way that
it would cause Mozilla to crash or execute arbitrary code when the
image was viewed. (CVE-2004-0597, CVE-2004-0599)

Zen Parse reported a flaw in the POP3 capability. A malicious POP3
server could send a carefully crafted response that would cause a heap
overflow and potentially allow execution of arbitrary code as the user
running Mozilla. (CVE-2004-0757)

Marcel Boesch found a flaw that allows a CA certificate to be imported
with a DN the same as that of the built-in CA root certificates, which
can cause a denial of service to SSL pages, as the malicious
certificate is treated as invalid. (CVE-2004-0758)

Met - Martin Hassman reported a flaw in Mozilla that could allow
malicious JavaScript code to upload local files from a users machine
without requiring confirmation. (CVE-2004-0759)

Mindlock Security reported a flaw in ftp URI handling. By using a NULL
character (%00) in a ftp URI, Mozilla can be confused into opening a
resource as a different MIME type. (CVE-2004-0760)

Mozilla does not properly prevent a frame in one domain from injecting
content into a frame that belongs to another domain, which facilitates
website spoofing and other attacks, also known as the frame injection
vulnerability. (CVE-2004-0718)

Tolga Tarhan reported a flaw that can allow a malicious webpage to use
a redirect sequence to spoof the security lock icon that makes a
webpage appear to be encrypted. (CVE-2004-0761)

Jesse Ruderman reported a security issue that affects a number of
browsers including Mozilla that could allow malicious websites to
install arbitrary extensions by using interactive events to manipulate
the XPInstall Security dialog box. (CVE-2004-0762)

Emmanouel Kellinis discovered a caching flaw in Mozilla which allows
malicious websites to spoof certificates of trusted websites via
redirects and JavaScript that uses the 'onunload' method.
(CVE-2004-0763)

Mozilla allowed malicious websites to hijack the user interface via
the 'chrome' flag and XML User Interface Language (XUL) files.
(CVE-2004-0764)

The cert_TestHostName function in Mozilla only checks the hostname
portion of a certificate when the hostname portion of the URI is not a
fully qualified domain name (FQDN). This flaw could be used for
spoofing if an attacker had control of machines on a default DNS
search path. (CVE-2004-0765)

All users are advised to update to these erratum packages which
contain a snapshot of Mozilla 1.4.3 including backported fixes and are
not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0599.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0722.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0757.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0759.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0760.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0761.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0762.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0763.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0764.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0765.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=236618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=251381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=229374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=249004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=241924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=250906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=246448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=240053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=162020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=253121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=244965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=234058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-421.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/09");
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
  rhsa = "RHSA-2004:421";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"galeon-1.2.13-3.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-chat-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-devel-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-dom-inspector-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-js-debugger-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-mail-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-devel-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-1.4.3-2.1.2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-devel-1.4.3-2.1.2")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mozilla-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-chat-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-devel-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-dom-inspector-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-js-debugger-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-mail-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-devel-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-1.4.3-3.0.2")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-devel-1.4.3-3.0.2")) flag++;

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
