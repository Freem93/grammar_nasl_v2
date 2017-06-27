#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0499. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47117);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2008-5913", "CVE-2010-0163", "CVE-2010-0183", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-3171");
  script_bugtraq_id(38831);
  script_osvdb_id(53341, 63263, 63457, 63479, 65734, 65735, 65739, 65742, 65744, 65749, 65750, 65751, 65752);
  script_xref(name:"RHSA", value:"2010:0499");

  script_name(english:"RHEL 3 / 4 : seamonkey (RHSA-2010:0499)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security issues are now
available for Red Hat Enterprise Linux 3 and 4.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

SeaMonkey is an open source web browser, email and newsgroup client,
IRC chat client, and HTML editor.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code with the privileges of the
user running SeaMonkey. (CVE-2010-1200)

A flaw was found in the way browser plug-ins interact. It was possible
for a plug-in to reference the freed memory from a different plug-in,
resulting in the execution of arbitrary code with the privileges of
the user running SeaMonkey. (CVE-2010-1198)

An integer overflow flaw was found in the processing of malformed web
content. A web page containing malicious content could cause SeaMonkey
to crash or, potentially, execute arbitrary code with the privileges
of the user running SeaMonkey. (CVE-2010-1199)

A flaw was found in the way SeaMonkey processed mail attachments. A
specially crafted mail message could cause SeaMonkey to crash.
(CVE-2010-0163)

A flaw was found in the way SeaMonkey handled the
'Content-Disposition: attachment' HTTP header when the 'Content-Type:
multipart' HTTP header was also present. A website that allows
arbitrary uploads and relies on the 'Content-Disposition: attachment'
HTTP header to prevent content from being displayed inline, could be
used by an attacker to serve malicious content to users.
(CVE-2010-1197)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1198.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1199.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0499.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0499";
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
  if (rpm_check(release:"RHEL3", reference:"seamonkey-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-chat-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-devel-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-dom-inspector-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-js-debugger-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-mail-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-nspr-devel-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-1.0.9-0.55.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"seamonkey-nss-devel-1.0.9-0.55.el3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"seamonkey-1.0.9-58.el4_8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-chat-1.0.9-58.el4_8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-devel-1.0.9-58.el4_8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-dom-inspector-1.0.9-58.el4_8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-js-debugger-1.0.9-58.el4_8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"seamonkey-mail-1.0.9-58.el4_8")) flag++;


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
