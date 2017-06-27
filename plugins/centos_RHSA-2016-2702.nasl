#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2702 and 
# CentOS Errata and Security Advisory 2016:2702 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94978);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/01/23 15:31:52 $");

  script_cve_id("CVE-2016-7545");
  script_osvdb_id(144760);
  script_xref(name:"RHSA", value:"2016:2702");

  script_name(english:"CentOS 6 / 7 : policycoreutils (CESA-2016:2702)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for policycoreutils is now available for Red Hat Enterprise
Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The policycoreutils packages contain the core policy utilities
required to manage a SELinux environment.

Security Fix(es) :

* It was found that the sandbox tool provided in policycoreutils was
vulnerable to a TIOCSTI ioctl attack. A specially crafted program
executed via the sandbox command could use this flaw to execute
arbitrary commands in the context of the parent shell, escaping the
sandbox. (CVE-2016-7545)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-November/022147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?608f0723"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003686.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f87d7845"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected policycoreutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:policycoreutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:policycoreutils-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:policycoreutils-newrole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:policycoreutils-restorecond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:policycoreutils-sandbox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"policycoreutils-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"policycoreutils-gui-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"policycoreutils-newrole-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"policycoreutils-python-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"policycoreutils-sandbox-2.0.83-30.1.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"policycoreutils-2.5-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"policycoreutils-devel-2.5-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"policycoreutils-gui-2.5-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"policycoreutils-newrole-2.5-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"policycoreutils-python-2.5-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"policycoreutils-restorecond-2.5-9.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"policycoreutils-sandbox-2.5-9.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
