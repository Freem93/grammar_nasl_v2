#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:512. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18512);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2004-1009", "CVE-2004-1090", "CVE-2004-1091", "CVE-2004-1093", "CVE-2004-1174", "CVE-2004-1175", "CVE-2005-0763");
  script_osvdb_id(12904, 12905, 12906, 12908, 12909, 12910, 15170);
  script_xref(name:"RHSA", value:"2005:512");

  script_name(english:"RHEL 2.1 : mc (RHSA-2005:512)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mc packages that fix several security issues are now available
for Red Hat Enterprise Linux 2.1.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Midnight Commander is a visual shell much like a file manager.

Several denial of service bugs were found in Midnight Commander. These
bugs could cause Midnight Commander to hang or crash if a victim opens
a carefully crafted file. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the names CVE-2004-1009,
CVE-2004-1090, CVE-2004-1091, CVE-2004-1093 and CVE-2004-1174 to these
issues.

A filename quoting bug was found in Midnight Commander's FISH protocol
handler. If a victim connects via embedded SSH support to a host
containing a carefully crafted filename, arbitrary code may be
executed as the user running Midnight Commander. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-1175 to this issue.

A buffer overflow bug was found in the way Midnight Commander handles
directory completion. If a victim uses completion on a maliciously
crafted directory path, it is possible for arbitrary code to be
executed as the user running Midnight Commander. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0763 to this issue.

Users of mc are advised to upgrade to these packages, which contain
backported security patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1091.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1175.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0763.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-512.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gmc, mc and / or mcserv packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gmc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mcserv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:512";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"gmc-4.5.51-36.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mc-4.5.51-36.8")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mcserv-4.5.51-36.8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gmc / mc / mcserv");
  }
}
