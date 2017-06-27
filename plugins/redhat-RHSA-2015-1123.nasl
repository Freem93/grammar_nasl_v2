#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1123. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84258);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2014-9679", "CVE-2015-1158", "CVE-2015-1159");
  script_bugtraq_id(72594, 75098, 75106);
  script_osvdb_id(118237, 123116, 123117);
  script_xref(name:"RHSA", value:"2015:1123");

  script_name(english:"RHEL 6 / 7 : cups (RHSA-2015:1123)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

CUPS provides a portable printing layer for Linux, UNIX, and similar
operating systems.

A string reference count bug was found in cupsd, causing premature
freeing of string objects. An attacker can submit a malicious print
job that exploits this flaw to dismantle ACLs protecting privileged
operations, allowing a replacement configuration file to be uploaded
which in turn allows the attacker to run arbitrary code in the CUPS
server (CVE-2015-1158)

A cross-site scripting flaw was found in the cups web templating
engine. An attacker could use this flaw to bypass the default
configuration settings that bind the CUPS scheduler to the 'localhost'
or loopback interface. (CVE-2015-1159)

An integer overflow leading to a heap-based buffer overflow was found
in the way cups handled compressed raster image files. An attacker
could create a specially crafted image file, which when passed via the
cups Raster filter, could cause the cups filter to crash.
(CVE-2014-9679)

Red Hat would like to thank the CERT/CC for reporting CVE-2015-1158
and CVE-2015-1159 issues.

All cups users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, the cupsd daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9679.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1123.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-ipptool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1123";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cups-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cups-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cups-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"cups-debuginfo-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"cups-devel-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"cups-libs-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cups-lpd-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cups-lpd-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cups-lpd-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"cups-php-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"cups-php-1.4.2-67.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"cups-php-1.4.2-67.el6_6.1")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"cups-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cups-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"cups-client-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cups-client-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"cups-debuginfo-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"cups-devel-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"cups-filesystem-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"cups-ipptool-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cups-ipptool-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"cups-libs-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"cups-lpd-1.6.3-17.el7_1.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cups-lpd-1.6.3-17.el7_1.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-client / cups-debuginfo / cups-devel / cups-filesystem / etc");
  }
}
