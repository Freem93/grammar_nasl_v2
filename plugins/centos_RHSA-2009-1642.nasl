#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1642 and 
# CentOS Errata and Security Advisory 2009:1642 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43810);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/20 05:01:05 $");

  script_cve_id("CVE-2009-4033", "CVE-2009-4235");
  script_osvdb_id(60851, 60870);
  script_xref(name:"RHSA", value:"2009:1642");
  script_xref(name:"IAVA", value:"2009-A-0135");

  script_name(english:"CentOS 5 : acpid (CESA-2009:1642)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated acpid package that fixes one security issue is now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

acpid is a daemon that dispatches ACPI (Advanced Configuration and
Power Interface) events to user-space programs.

It was discovered that acpid could create its log file
('/var/log/acpid') with random permissions on some systems. A local
attacker could use this flaw to escalate their privileges if the log
file was created as world-writable and with the setuid or setgid bit
set. (CVE-2009-4033)

Please note that this flaw was due to a Red Hat-specific patch
(acpid-1.0.4-fd.patch) included in the Red Hat Enterprise Linux 5
acpid package.

Users are advised to upgrade to this updated package, which contains a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016380.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3e27f70"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016381.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fefeea9c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected acpid package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:acpid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"acpid-1.0.4-9.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
