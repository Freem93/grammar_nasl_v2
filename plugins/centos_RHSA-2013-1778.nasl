#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1778 and 
# CentOS Errata and Security Advisory 2013:1778 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71178);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2012-5576", "CVE-2013-1913", "CVE-2013-1978");
  script_bugtraq_id(56647, 64098, 64105);
  script_osvdb_id(87792, 100614, 100615);
  script_xref(name:"RHSA", value:"2013:1778");

  script_name(english:"CentOS 5 / 6 : gimp (CESA-2013:1778)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gimp packages that fix three security issues are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

A stack-based buffer overflow flaw, a heap-based buffer overflow, and
an integer overflow flaw were found in the way GIMP loaded certain X
Window System (XWD) image dump files. A remote attacker could provide
a specially crafted XWD image file that, when processed, would cause
the XWD plug-in to crash or, potentially, execute arbitrary code with
the privileges of the user running the GIMP. (CVE-2012-5576,
CVE-2013-1913, CVE-2013-1978)

The CVE-2013-1913 and CVE-2013-1978 issues were discovered by Murray
McAllister of the Red Hat Security Response Team.

Users of the GIMP are advised to upgrade to these updated packages,
which correct these issues. The GIMP must be restarted for the update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9ffd887"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d0d4e4c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-devel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-help-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
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
if (rpm_check(release:"CentOS-5", reference:"gimp-2.2.13-3.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gimp-devel-2.2.13-3.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gimp-libs-2.2.13-3.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"gimp-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gimp-devel-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gimp-devel-tools-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gimp-help-browser-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gimp-libs-2.6.9-6.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
