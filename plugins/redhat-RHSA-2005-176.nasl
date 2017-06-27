#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:176. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17252);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2004-1156", "CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0255", "CVE-2005-0527", "CVE-2005-0578", "CVE-2005-0584", "CVE-2005-0585", "CVE-2005-0586", "CVE-2005-0588", "CVE-2005-0589", "CVE-2005-0590", "CVE-2005-0591", "CVE-2005-0592", "CVE-2005-0593");
  script_xref(name:"RHSA", value:"2005:176");

  script_name(english:"RHEL 4 : firefox (RHSA-2005:176)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix various bugs are now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

A bug was found in the Firefox string handling functions. If a
malicious website is able to exhaust a system's memory, it becomes
possible to execute arbitrary code. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0255
to this issue.

A bug was found in the way Firefox handles pop-up windows. It is
possible for a malicious website to control the content in an
unrelated site's pop-up window. (CVE-2004-1156)

A bug was found in the way Firefox allows plug-ins to load privileged
content into a frame. It is possible that a malicious webpage could
trick a user into clicking in certain places to modify configuration
settings or execute arbitrary code. (CVE-2005-0232 and CVE-2005-0527).

A flaw was found in the way Firefox displays international domain
names. It is possible for an attacker to display a valid URL, tricking
the user into thinking they are viewing a legitimate webpage when they
are not. (CVE-2005-0233)

A bug was found in the way Firefox handles plug-in temporary files. A
malicious local user could create a symlink to a victims directory,
causing it to be deleted when the victim exits Firefox.
(CVE-2005-0578)

A bug has been found in one of Firefox's UTF-8 converters. It may be
possible for an attacker to supply a specially crafted UTF-8 string to
the buggy converter, leading to arbitrary code execution.
(CVE-2005-0592)

A bug was found in the Firefox JavaScript security manager. If a user
drags a malicious link to a tab, the JavaScript security manager is
bypassed which could result in remote code execution or information
disclosure. (CVE-2005-0231)

A bug was found in the way Firefox displays the HTTP authentication
prompt. When a user is prompted for authentication, the dialog window
is displayed over the active tab, regardless of the tab that caused
the pop-up to appear and could trick a user into entering their
username and password for a trusted site. (CVE-2005-0584)

A bug was found in the way Firefox displays the save file dialog. It
is possible for a malicious webserver to spoof the Content-Disposition
header, tricking the user into thinking they are downloading a
different filetype. (CVE-2005-0586)

A bug was found in the way Firefox handles users 'down-arrow' through
auto completed choices. When an autocomplete choice is selected, the
information is copied into the input control, possibly allowing a
malicious website to steal information by tricking a user into
arrowing through autocompletion choices. (CVE-2005-0589)

Several bugs were found in the way Firefox displays the secure site
icon. It is possible that a malicious website could display the secure
site icon along with incorrect certificate information.
(CVE-2005-0593)

A bug was found in the way Firefox displays the download dialog
window. A malicious site can obfuscate the content displayed in the
source field, tricking a user into thinking they are downloading
content from a trusted source. (CVE-2005-0585)

A bug was found in the way Firefox handles xsl:include and xsl:import
directives. It is possible for a malicious website to import XSLT
stylesheets from a domain behind a firewall, leaking information to an
attacker. (CVE-2005-0588)

A bug was found in the way Firefox displays the installation
confirmation dialog. An attacker could add a long user:pass before the
true hostname, tricking a user into thinking they were installing
content from a trusted source. (CVE-2005-0590)

A bug was found in the way Firefox displays download and security
dialogs. An attacker could cover up part of a dialog window tricking
the user into clicking 'Allow' or 'Open', which could potentially lead
to arbitrary code execution. (CVE-2005-0591)

Users of Firefox are advised to upgrade to this updated package which
contains Firefox version 1.0.1 and is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1156.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0255.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0589.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0592.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-176.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/02");
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
  rhsa = "RHSA-2005:176";
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
  if (rpm_check(release:"RHEL4", reference:"firefox-1.0.1-1.4.3")) flag++;

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
