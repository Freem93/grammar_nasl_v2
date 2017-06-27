#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0199. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20857);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/29 15:35:19 $");

  script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");
  script_osvdb_id(21533, 22890, 22892, 79168, 79169);
  script_xref(name:"RHSA", value:"2006:0199");

  script_name(english:"RHEL 2.1 / 3 / 4 : mozilla (RHSA-2006:0199)");
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

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Igor Bukanov discovered a bug in the way Mozilla's JavaScript
interpreter dereferences objects. If a user visits a malicious web
page, Mozilla could crash or execute arbitrary code as the user
running Mozilla. The Common Vulnerabilities and Exposures project
assigned the name CVE-2006-0292 to this issue.

moz_bug_r_a4 discovered a bug in Mozilla's XULDocument.persist()
function. A malicious web page could inject arbitrary RDF data into a
user's localstore.rdf file, which can cause Mozilla to execute
arbitrary JavaScript when a user runs Mozilla. (CVE-2006-0296)

A denial of service bug was found in the way Mozilla saves history
information. If a user visits a web page with a very long title, it is
possible Mozilla will crash or take a very long time the next time it
is run. (CVE-2005-4134)

Note that the Red Hat Enterprise Linux 3 packages also fix a bug when
using XSLT to transform documents. Passing DOM Nodes as parameters to
functions expecting an xsl:param could cause Mozilla to throw an
exception.

Users of Mozilla are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-4134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0292.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0199.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/07");
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
  rhsa = "RHSA-2006:0199";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-chat-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-devel-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-dom-inspector-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-js-debugger-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-mail-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nspr-devel-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-1.7.12-1.1.2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mozilla-nss-devel-1.7.12-1.1.2.3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mozilla-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-chat-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-devel-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-dom-inspector-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-js-debugger-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-mail-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nspr-devel-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-1.7.12-1.1.3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mozilla-nss-devel-1.7.12-1.1.3.4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"mozilla-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-chat-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-devel-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-dom-inspector-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-js-debugger-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-mail-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nspr-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nspr-devel-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nss-1.7.12-1.4.2")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mozilla-nss-devel-1.7.12-1.4.2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla / mozilla-chat / mozilla-devel / mozilla-dom-inspector / etc");
  }
}
