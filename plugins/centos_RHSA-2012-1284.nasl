#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1284 and 
# CentOS Errata and Security Advisory 2012:1284 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62187);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/28 14:01:46 $");

  script_cve_id("CVE-2012-4425");
  script_bugtraq_id(55555);
  script_osvdb_id(85551);
  script_xref(name:"RHSA", value:"2012:1284");

  script_name(english:"CentOS 6 : spice-gtk (CESA-2012:1284)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spice-gtk packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for SPICE
(Simple Protocol for Independent Computing Environments) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of
this widget to access virtual machines using the SPICE protocol.

It was discovered that the spice-gtk setuid helper application,
spice-client-glib-usb-acl-helper, did not clear the environment
variables read by the libraries it uses. A local attacker could
possibly use this flaw to escalate their privileges by setting
specific environment variables before running the helper application.
(CVE-2012-4425)

Red Hat would like to thank Sebastian Krahmer of the SUSE Security
Team for reporting this issue.

All users of spice-gtk are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018886.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41d9dfc6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-gtk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"spice-glib-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-glib-devel-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-gtk-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-gtk-devel-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-gtk-python-0.11-11.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-gtk-tools-0.11-11.el6_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
