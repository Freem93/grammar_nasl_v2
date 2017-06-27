#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1273 and 
# CentOS Errata and Security Advisory 2013:1273 respectively.
#

include("compat.inc");

if (description)
{
  script_id(70000);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/06 23:41:35 $");

  script_cve_id("CVE-2013-4324");
  script_osvdb_id(97508);
  script_xref(name:"RHSA", value:"2013:1273");

  script_name(english:"CentOS 6 : spice-gtk (CESA-2013:1273)");
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
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for SPICE
(Simple Protocol for Independent Computing Environments) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of
this widget to access virtual machines using the SPICE protocol.

spice-gtk communicated with PolicyKit for authorization via an API
that is vulnerable to a race condition. This could lead to intended
PolicyKit authorizations being bypassed. This update modifies
spice-gtk to communicate with PolicyKit via a different API that is
not vulnerable to the race condition. (CVE-2013-4324)

All users of spice-gtk are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-September/019950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d38221fc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-gtk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"spice-glib-0.14-7.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-glib-devel-0.14-7.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-gtk-0.14-7.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-gtk-devel-0.14-7.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-gtk-python-0.14-7.el6_4.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"spice-gtk-tools-0.14-7.el6_4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
