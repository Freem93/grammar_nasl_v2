#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0188 and 
# CentOS Errata and Security Advisory 2016:0188 respectively.
#

include("compat.inc");

if (description)
{
  script_id(88760);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/02/17 15:19:24 $");

  script_cve_id("CVE-2015-7529");
  script_xref(name:"RHSA", value:"2016:0188");

  script_name(english:"CentOS 7 : sos (CESA-2016:0188)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sos package that fixes one security issue and one bug is
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The sos package contains a set of utilities that gather information
from system hardware, logs, and configuration files. The information
can then be used for diagnostic purposes and debugging.

An insecure temporary file use flaw was found in the way sos created
certain sosreport files. A local attacker could possibly use this flaw
to perform a symbolic link attack to reveal the contents of sosreport
files, or in some cases modify arbitrary files and escalate their
privileges on the system. (CVE-2015-7529)

This issue was discovered by Mateusz Guzik of Red Hat.

This update also fixes the following bug :

* Previously, the sosreport tool was not collecting the /var/lib/ceph
and /var/run/ceph directories when run with the ceph plug-in enabled,
causing the generated sosreport archive to miss vital troubleshooting
information about ceph. With this update, the ceph plug-in for
sosreport collects these directories, and the generated report
contains more useful information. (BZ#1291347)

All users of sos are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-February/021704.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f19ad878"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sos package.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sos");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sos-3.2-35.el7.centos.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
