#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0703. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49301);
  script_version ("$Revision: 1.25 $");
  script_cvs_date("$Date: 2017/01/05 14:44:34 $");

  script_cve_id("CVE-2010-0405");
  script_bugtraq_id(43331);
  script_osvdb_id(68167);
  script_xref(name:"RHSA", value:"2010:0703");
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"RHEL 3 / 4 / 5 : bzip2 (RHSA-2010:0703)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bzip2 packages that fix one security issue are now available
for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

bzip2 is a freely available, high-quality data compressor. It provides
both standalone compression and decompression utilities, as well as a
shared library for use with other programs.

An integer overflow flaw was discovered in the bzip2 decompression
routine. This issue could, when decompressing malformed archives,
cause bzip2, or an application linked against the libbz2 library, to
crash or, potentially, execute arbitrary code. (CVE-2010-0405)

Users of bzip2 should upgrade to these updated packages, which contain
a backported patch to resolve this issue. All running applications
using the libbz2 library must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0405.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0703.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzip2, bzip2-devel and / or bzip2-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0703";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL3", reference:"bzip2-1.0.2-14.EL3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bzip2-devel-1.0.2-14.EL3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bzip2-libs-1.0.2-14.EL3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"bzip2-1.0.2-16.el4_8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bzip2-devel-1.0.2-16.el4_8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bzip2-libs-1.0.2-16.el4_8")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bzip2-1.0.3-6.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bzip2-1.0.3-6.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bzip2-1.0.3-6.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bzip2-devel-1.0.3-6.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bzip2-libs-1.0.3-6.el5_5")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bzip2 / bzip2-devel / bzip2-libs");
  }
}
