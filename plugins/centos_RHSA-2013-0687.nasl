#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0687 and 
# CentOS Errata and Security Advisory 2013:0687 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65725);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-1591");
  script_bugtraq_id(58193);
  script_osvdb_id(90194);
  script_xref(name:"RHSA", value:"2013:0687");

  script_name(english:"CentOS 6 : pixman (CESA-2013:0687)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pixman packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Pixman is a pixel manipulation library for the X Window System and
Cairo.

An integer overflow flaw was discovered in one of pixman's
manipulation routines. If a remote attacker could trick an application
using pixman into performing a certain manipulation, it could cause
the application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2013-1591)

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct this issue. All applications using
pixman must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019670.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8a702e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pixman packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pixman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pixman-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"pixman-0.26.2-5.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pixman-devel-0.26.2-5.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
