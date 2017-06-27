#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:335. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17626);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2004-1156", "CVE-2004-1316", "CVE-2004-1380", "CVE-2004-1381", "CVE-2005-0141", "CVE-2005-0142", "CVE-2005-0143", "CVE-2005-0144", "CVE-2005-0146", "CVE-2005-0147", "CVE-2005-0149", "CVE-2005-0233", "CVE-2005-0399", "CVE-2005-0401", "CVE-2005-0585");
  script_xref(name:"RHSA", value:"2005:335");

  script_name(english:"RHEL 4 : mozilla (RHSA-2005:335)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix various bugs are now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

A buffer overflow bug was found in the way Mozilla processes GIF
images. It is possible for an attacker to create a specially crafted
GIF image, which when viewed by a victim will execute arbitrary code
as the victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0399 to this issue.

A bug was found in the way Mozilla responds to proxy auth requests. It
is possible for a malicious webserver to steal credentials from a
victims browser by issuing a 407 proxy authentication request.
(CVE-2005-0147)

A bug was found in the way Mozilla displays dialog windows. It is
possible that a malicious web page which is being displayed in a
background tab could present the user with a dialog window appearing
to come from the active page. (CVE-2004-1380)

A bug was found in the way Mozilla Mail handles cookies when loading
content over HTTP regardless of the user's preference. It is possible
that a particular user could be tracked through the use of malicious
mail messages which load content over HTTP. (CVE-2005-0149)

A flaw was found in the way Mozilla displays international domain
names. It is possible for an attacker to display a valid URL, tricking
the user into thinking they are viewing a legitimate webpage when they
are not. (CVE-2005-0233)

A bug was found in the way Mozilla handles pop-up windows. It is
possible for a malicious website to control the content in an
unrelated site's pop-up window. (CVE-2004-1156)

A bug was found in the way Mozilla saves temporary files. Temporary
files are saved with world readable permissions, which could allow a
local malicious user to view potentially sensitive data.
(CVE-2005-0142)

A bug was found in the way Mozilla handles synthetic middle click
events. It is possible for a malicious web page to steal the contents
of a victims clipboard. (CVE-2005-0146)

A bug was found in the way Mozilla processes XUL content. If a
malicious web page can trick a user into dragging an object, it is
possible to load malicious XUL content. (CVE-2005-0401)

A bug was found in the way Mozilla loads links in a new tab which are
middle clicked. A malicious web page could read local files or modify
privileged chrom settings. (CVE-2005-0141)

A bug was found in the way Mozilla displays the secure site icon. A
malicious web page can use a view-source URL targetted at a secure
page, while loading an insecure page, yet the secure site icon shows
the previous secure state. (CVE-2005-0144)

A bug was found in the way Mozilla displays the secure site icon. A
malicious web page can display the secure site icon by loading a
binary file from a secured site. (CVE-2005-0143)

A bug was found in the way Mozilla displays the download dialog
window. A malicious site can obfuscate the content displayed in the
source field, tricking a user into thinking they are downloading
content from a trusted source. (CVE-2005-0585)

Users of Mozilla are advised to upgrade to this updated package which
contains Mozilla version 1.7.6 to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1380.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0141.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0144.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0149.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0399.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-335.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:evolution-devel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/25");
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
  rhsa = "RHSA-2005:335";
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
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-0.9.2-2.4.3")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-0.9.2-2.4.3")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"devhelp-devel-0.9.2-2.4.3")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"devhelp-devel-0.9.2-2.4.3")) flag++;
  if (rpm_check(release:"RHEL4", reference:"evolution-2.0.2-14")) flag++;
  if (rpm_check(release:"RHEL4", reference:"evolution-devel-2.0.2-14")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-chat-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-devel-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-dom-inspector-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-js-debugger-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-mail-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nspr-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nspr-devel-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nss-1.7.6-1.4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nss-devel-1.7.6-1.4.1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-devel / evolution / evolution-devel / mozilla / etc");
  }
}
