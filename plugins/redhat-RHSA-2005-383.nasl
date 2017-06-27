#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:383. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18109);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2005-0752", "CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160");
  script_osvdb_id(15241, 15682, 15683, 15684, 15685, 15686, 15687, 15688, 15689, 15690);
  script_xref(name:"RHSA", value:"2005:383");

  script_name(english:"RHEL 4 : firefox (RHSA-2005:383)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix various security bugs are now
available.

This update has been rated as having Important security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Vladimir V. Perepelitsa discovered a bug in the way Firefox handles
anonymous functions during regular expression string replacement. It
is possible for a malicious web page to capture a random block of
browser memory. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0989 to this issue.

Omar Khan discovered a bug in the way Firefox processes the
PLUGINSPAGE tag. It is possible for a malicious web page to trick a
user into pressing the 'manual install' button for an unknown plugin
leading to arbitrary JavaScript code execution. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0752 to this issue.

Doron Rosenberg discovered a bug in the way Firefox displays pop-up
windows. If a user choses to open a pop-up window whose URL is
malicious JavaScript, the script will be executed with elevated
privileges. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1153 to this issue.

A bug was found in the way Firefox handles the JavaScript global scope
for a window. It is possible for a malicious web page to define a
global variable known to be used by a different site, allowing
malicious code to be executed in the context of the site. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-1154 to this issue.

Michael Krax discovered a bug in the way Firefox handles favicon
links. A malicious web page can programatically define a favicon link
tag as JavaScript, executing arbitrary JavaScript with elevated
privileges. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1155 to this issue.

Michael Krax discovered a bug in the way Firefox installed search
plugins. If a user chooses to install a search plugin from a malicious
site, the new plugin could silently overwrite an existing plugin. This
could allow the malicious plugin to execute arbitrary code and steal
sensitive information. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the names CVE-2005-1156 and
CVE-2005-1157 to these issues.

Kohei Yoshino discovered a bug in the way Firefox opens links in its
sidebar. A malicious web page could construct a link in such a way
that, when clicked on, could execute arbitrary JavaScript with
elevated privileges. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1158 to this issue.

A bug was found in the way Firefox validated several XPInstall related
JavaScript objects. A malicious web page could pass other objects to
the XPInstall objects, resulting in the JavaScript interpreter jumping
to arbitrary locations in memory. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-1159
to this issue.

A bug was found in the way the Firefox privileged UI code handled DOM
nodes from the content window. A malicious web page could install
malicious JavaScript code or steal data requiring a user to do
commonplace actions such as clicking a link or opening the context
menu. The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2005-1160 to this issue.

Users of Firefox are advised to upgrade to this updated package which
contains Firefox version 1.0.3 and is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0752.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1158.html"
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
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-383.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/31");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:383";
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
  if (rpm_check(release:"RHEL4", reference:"firefox-1.0.3-1.4.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
  }
}
