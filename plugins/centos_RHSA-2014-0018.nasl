#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0018 and 
# CentOS Errata and Security Advisory 2014:0018 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71901);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/10 14:11:45 $");

  script_cve_id("CVE-2013-6462");
  script_osvdb_id(101842);
  script_xref(name:"RHSA", value:"2014:0018");

  script_name(english:"CentOS 5 / 6 : libXfont (CESA-2014:0018)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libXfont packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The libXfont packages provide the X.Org libXfont runtime library.
X.Org is an open source implementation of the X Window System.

A stack-based buffer overflow flaw was found in the way the libXfont
library parsed Glyph Bitmap Distribution Format (BDF) fonts. A
malicious, local user could exploit this issue to potentially execute
arbitrary code with the privileges of the X.Org server.
(CVE-2013-6462)

Users of libXfont should upgrade to these updated packages, which
contain a backported patch to resolve this issue. All running X.Org
server instances must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-January/020103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?844d0a80"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-January/020104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f810661d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxfont packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/12");
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
if (rpm_check(release:"CentOS-5", reference:"libXfont-1.2.2-1.0.5.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libXfont-devel-1.2.2-1.0.5.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libXfont-1.4.5-3.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXfont-devel-1.4.5-3.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
