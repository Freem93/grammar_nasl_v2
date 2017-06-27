#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:825 and 
# CentOS Errata and Security Advisory 2005:825 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21968);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2672");
  script_osvdb_id(18905);
  script_xref(name:"RHSA", value:"2005:825");

  script_name(english:"CentOS 4 : lm_sensors (CESA-2005:825)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated lm_sensors packages that fix an insecure file issue are now
available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The lm_sensors package includes a collection of modules for general
SMBus access and hardware monitoring. This package requires special
support which is not in standard version 2.2 kernels.

A bug was found in the way the pwmconfig tool creates temporary files.
It is possible that a local attacker could leverage this flaw to
overwrite arbitrary files located on the system. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-2672 to this issue.

Users of lm_sensors are advised to upgrade to these updated packages,
which contain a backported patch that resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d95ee84"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012397.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2415488f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lm_sensors packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lm_sensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lm_sensors-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"lm_sensors-2.8.7-2.40.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"lm_sensors-2.8.7-2.40.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"lm_sensors-devel-2.8.7-2.40.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"lm_sensors-devel-2.8.7-2.40.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
