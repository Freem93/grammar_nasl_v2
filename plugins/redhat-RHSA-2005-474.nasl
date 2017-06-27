#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:474. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18510);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2005-0758", "CVE-2005-0953", "CVE-2005-1260");
  script_osvdb_id(15237, 16371, 16767);
  script_xref(name:"RHSA", value:"2005:474");

  script_name(english:"RHEL 2.1 / 3 / 4 : bzip2 (RHSA-2005:474)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bzip2 packages that fix multiple issues are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

[Updated 13 February 2006] Replacement bzip2 packages for Red Hat
Enterprise Linux 4 have been created as the original erratum packages
did not fix CVE-2005-0758.

Bzip2 is a data compressor.

A bug was found in the way bzgrep processes file names. If a user can
be tricked into running bzgrep on a file with a carefully crafted file
name, arbitrary commands could be executed as the user running bzgrep.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0758 to this issue.

A bug was found in the way bzip2 modifies file permissions during
decompression. If an attacker has write access to the directory into
which bzip2 is decompressing files, it is possible for them to modify
permissions on files owned by the user running bzip2 (CVE-2005-0953).

A bug was found in the way bzip2 decompresses files. It is possible
for an attacker to create a specially crafted bzip2 file which will
cause bzip2 to cause a denial of service (by filling disk space) if
decompressed by a victim (CVE-2005-1260).

Users of Bzip2 should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0953.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1260.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://scary.beasts.org/security/CESA-2005-002.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-474.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzip2, bzip2-devel and / or bzip2-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/30");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:474";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bzip2-1.0.1-4.EL2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bzip2-devel-1.0.1-4.EL2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bzip2-libs-1.0.1-4.EL2.1")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bzip2-1.0.2-11.EL3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"bzip2-devel-1.0.2-11.EL3.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"bzip2-libs-1.0.2-11.EL3.4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bzip2-1.0.2-13.EL4.3")) flag++;
  if (rpm_check(release:"RHEL4", reference:"bzip2-devel-1.0.2-13.EL4.3")) flag++;
  if (rpm_check(release:"RHEL4", reference:"bzip2-libs-1.0.2-13.EL4.3")) flag++;

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
