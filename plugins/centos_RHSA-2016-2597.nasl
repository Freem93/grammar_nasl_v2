#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2597 and 
# CentOS Errata and Security Advisory 2016:2597 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95343);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/26 13:35:46 $");

  script_cve_id("CVE-2016-5410");
  script_osvdb_id(143037);
  script_xref(name:"RHSA", value:"2016:2597");

  script_name(english:"CentOS 7 : firewalld (CESA-2016:2597)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for firewalld is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

firewalld is a firewall service daemon that provides a dynamic
customizable firewall with a D-Bus interface.

The following packages have been upgraded to a newer upstream version:
firewalld (0.4.3.2). (BZ#1302802)

Security Fix(es) :

* A flaw was found in the way firewalld allowed certain firewall
configurations to be modified by unauthenticated users. Any locally
logged in user could use this flaw to tamper or change firewall
settings. (CVE-2016-5410)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003591.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3dd49cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firewalld packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firewall-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firewall-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firewalld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firewalld-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-firewall");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firewall-applet-0.4.3.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firewall-config-0.4.3.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firewalld-0.4.3.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firewalld-filesystem-0.4.3.2-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-firewall-0.4.3.2-8.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
