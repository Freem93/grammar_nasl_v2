#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0127 and 
# CentOS Errata and Security Advisory 2014:0127 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72268);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/08/31 14:21:47 $");

  script_cve_id("CVE-2013-1881");
  script_bugtraq_id(62714);
  script_osvdb_id(98103);
  script_xref(name:"RHSA", value:"2014:0127");

  script_name(english:"CentOS 6 : librsvg2 (CESA-2014:0127)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated librsvg2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

[Updated Feb 4, 2014] The original packages distributed with this
advisory contained a bug that caused applications using librsvg2 to
crash when loading certain SVG images. We have updated the packages to
correct this bug.

The librsvg2 packages provide an SVG (Scalable Vector Graphics)
library based on libart.

An XML External Entity expansion flaw was found in the way librsvg2
processed SVG files. If a user were to open a malicious SVG file, a
remote attacker could possibly obtain a copy of the local resources
that the user had access to. (CVE-2013-1881)

All librsvg2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
applications that use librsvg2 must be restarted for this update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-February/020135.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58b65878"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected librsvg2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librsvg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:librsvg2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"librsvg2-2.26.0-6.el6_5.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"librsvg2-devel-2.26.0-6.el6_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
