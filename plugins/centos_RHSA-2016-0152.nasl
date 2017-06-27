#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0152 and 
# CentOS Errata and Security Advisory 2016:0152 respectively.
#

include("compat.inc");

if (description)
{
  script_id(88683);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/02/11 15:08:19 $");

  script_cve_id("CVE-2015-7529");
  script_xref(name:"RHSA", value:"2016:0152");

  script_name(english:"CentOS 6 : sos (CESA-2016:0152)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sos package that fixes one security issue and one bug is
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The sos package contains a set of tools that gather information from
system hardware, logs and configuration files. The information can
then be used for diagnostic purposes and debugging.

An insecure temporary file use flaw was found in the way sos created
certain sosreport files. A local attacker could possibly use this flaw
to perform a symbolic link attack to reveal the contents of sosreport
files, or in some cases modify arbitrary files and escalate their
privileges on the system. (CVE-2015-7529)

This issue was discovered by Mateusz Guzik of Red Hat.

This update also fixes the following bug :

* Previously, when the hpasm plug-in ran the 'hpasmcli' command in a
Python Popen constructor or a system pipeline, the command would hang
and eventually time out after 300 seconds. Sos was forced to wait for
the time out to finish, unnecessarily prolonging its run time. With
this update, the timeout of the 'hpasmcli' command has been set to 0,
eliminating the delay and speeding up sos completion time.
(BZ#1291828)

All sos users are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-February/021666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1fc4aa3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sos package.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/11");
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
if (rpm_check(release:"CentOS-6", reference:"sos-3.2-28.el6.centos.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
