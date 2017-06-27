#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0153. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31185);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/03 17:16:32 $");

  script_cve_id("CVE-2008-0596", "CVE-2008-0597");
  script_bugtraq_id(27988);
  script_osvdb_id(42158, 42159);
  script_xref(name:"RHSA", value:"2008:0153");

  script_name(english:"RHEL 3 : cups (RHSA-2008:0153)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fixes two security issues and a bug are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

A flaw was found in the way CUPS handled the addition and removal of
remote shared printers via IPP. A remote attacker could send malicious
UDP IPP packets causing the CUPS daemon to attempt to dereference
already freed memory and crash. (CVE-2008-0597)

A memory management flaw was found in the way CUPS handled the
addition and removal of remote shared printers via IPP. When shared
printer was removed, allocated memory was not properly freed, leading
to a memory leak possibly causing CUPS daemon crash after exhausting
available memory. (CVE-2008-0596)

These issues were found during the investigation of CVE-2008-0882,
which did not affect Red Hat Enterprise Linux 3.

Note that the default configuration of CUPS on Red Hat Enterprise
Linux 3 allow requests of this type only from the local subnet.

In addition, these updated cups packages fix a bug that occurred when
using the CUPS polling daemon. Excessive debugging log information was
saved to the error_log file regardless of the LogLevel setting, which
filled up disk space rapidly.

All CUPS users are advised to upgrade to these updated packages, which
contain backported patches to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0153.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups, cups-devel and / or cups-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0153";
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
  if (rpm_check(release:"RHEL3", reference:"cups-1.1.17-13.3.51")) flag++;
  if (rpm_check(release:"RHEL3", reference:"cups-devel-1.1.17-13.3.51")) flag++;
  if (rpm_check(release:"RHEL3", reference:"cups-libs-1.1.17-13.3.51")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
  }
}
