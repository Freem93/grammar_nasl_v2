#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:384. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18162);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2004-1156", "CVE-2005-0142", "CVE-2005-0143", "CVE-2005-0146", "CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0401", "CVE-2005-0527", "CVE-2005-0578", "CVE-2005-0584", "CVE-2005-0585", "CVE-2005-0586", "CVE-2005-0588", "CVE-2005-0590", "CVE-2005-0591", "CVE-2005-0593", "CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1159", "CVE-2005-1160");
  script_osvdb_id(11118, 12740, 12868, 13335, 13337, 13578, 13611, 13612, 14187, 14188, 14189, 14191, 14193, 14194, 14196, 14197, 14198, 15010, 15241, 15682, 15684, 15685, 15686, 15687, 15689, 15690, 59843);
  script_xref(name:"RHSA", value:"2005:384");

  script_name(english:"RHEL 2.1 / 3 : Mozilla (RHSA-2005:384)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Mozilla packages that fix various security bugs are now
available.

This update has been rated as having Important security impact by the
Red Hat Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several bugs were found with the way Mozilla displays the secure site
icon. It is possible that a malicious website could display the secure
site icon along with incorrect certificate information. (CVE-2005-0143
CVE-2005-0593)

A bug was found in the way Mozilla handles synthetic middle click
events. It is possible for a malicious web page to steal the contents
of a victims clipboard. (CVE-2005-0146)

Several bugs were found with the way Mozilla handles temporary files.
A local user could view sensitive temporary information or delete
arbitrary files. (CVE-2005-0142 CVE-2005-0578)

A bug was found in the way Mozilla handles pop-up windows. It is
possible for a malicious website to control the content in an
unrelated site's pop-up window. (CVE-2004-1156)

A flaw was found in the way Mozilla displays international domain
names. It is possible for an attacker to display a valid URL, tricking
the user into thinking they are viewing a legitimate webpage when they
are not. (CVE-2005-0233)

A bug was found in the way Mozilla processes XUL content. If a
malicious web page can trick a user into dragging an object, it is
possible to load malicious XUL content. (CVE-2005-0401)

A bug was found in the way Mozilla handles xsl:include and xsl:import
directives. It is possible for a malicious website to import XSLT
stylesheets from a domain behind a firewall, leaking information to an
attacker. (CVE-2005-0588)

Several bugs were found in the way Mozilla displays alert dialogs. It
is possible for a malicious webserver or website to trick a user into
thinking the dialog window is being generated from a trusted site.
(CVE-2005-0586 CVE-2005-0591 CVE-2005-0585 CVE-2005-0590
CVE-2005-0584)

A bug was found in the Mozilla JavaScript security manager. If a user
drags a malicious link to a tab, the JavaScript security manager is
bypassed, which could result in remote code execution or information
disclosure. (CVE-2005-0231)

A bug was found in the way Mozilla allows plug-ins to load privileged
content into a frame. It is possible that a malicious webpage could
trick a user into clicking in certain places to modify configuration
settings or execute arbitrary code. (CVE-2005-0232 and CVE-2005-0527)

A bug was found in the way Mozilla handles anonymous functions during
regular expression string replacement. It is possible for a malicious
web page to capture a random block of browser memory. (CVE-2005-0989)

A bug was found in the way Mozilla displays pop-up windows. If a user
choses to open a pop-up window whose URL is malicious JavaScript, the
script will be executed with elevated privileges. (CVE-2005-1153)

A bug was found in the way Mozilla installed search plugins. If a user
chooses to install a search plugin from a malicious site, the new
plugin could silently overwrite an existing plugin. This could allow
the malicious plugin to execute arbitrary code and stealm sensitive
information. (CVE-2005-1156 CVE-2005-1157)

Several bugs were found in the Mozilla JavaScript engine. A malicious
web page could leverage these issues to execute JavaScript with
elevated privileges or steal sensitive information. (CVE-2005-1154
CVE-2005-1155 CVE-2005-1159 CVE-2005-1160)

Users of Mozilla are advised to upgrade to this updated package which
contains Mozilla version 1.7.7 to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0142.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0233.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0586.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0989.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1154.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1155.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-384.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/29");
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
  rhsa = "RHSA-2005:384";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"galeon-1.2.14-1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-chat-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-devel-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-dom-inspector-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-js-debugger-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-mail-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-devel-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-1.7.7-1.1.2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-devel-1.7.7-1.1.2.1")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mozilla-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-chat-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-devel-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-dom-inspector-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-js-debugger-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-mail-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-devel-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-1.7.7-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-devel-1.7.7-1.1.3.4")) flag++;

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
