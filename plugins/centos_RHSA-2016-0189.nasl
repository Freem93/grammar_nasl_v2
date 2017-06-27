#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0189 and 
# CentOS Errata and Security Advisory 2016:0189 respectively.
#

include("compat.inc");

if (description)
{
  script_id(88761);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2015-3256");
  script_osvdb_id(126934);
  script_xref(name:"RHSA", value:"2016:0189");

  script_name(english:"CentOS 7 : polkit (CESA-2016:0189)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated polkit packages that fix one security issue are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

PolicyKit is a toolkit for defining and handling authorizations.

A denial of service flaw was found in how polkit handled authorization
requests. A local, unprivileged user could send malicious requests to
polkit, which could then cause the polkit daemon to corrupt its memory
and crash. (CVE-2015-3256)

All polkit users should upgrade to these updated packages, which
contain a backported patch to correct this issue. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-February/021675.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4391c29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected polkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:polkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:polkit-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"polkit-0.112-6.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"polkit-devel-0.112-6.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"polkit-docs-0.112-6.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
