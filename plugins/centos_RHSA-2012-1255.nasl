#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1255 and 
# CentOS Errata and Security Advisory 2012:1255 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62047);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_bugtraq_id(54437);
  script_osvdb_id(83753, 83754, 83755, 83757, 83758, 83759);
  script_xref(name:"RHSA", value:"2012:1255");

  script_name(english:"CentOS 5 / 6 : libexif (CESA-2012:1255)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libexif packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libexif packages provide an Exchangeable image file format (Exif)
library. Exif allows metadata to be added to and read from certain
types of image files.

Multiple flaws were found in the way libexif processed Exif tags. An
attacker could create a specially crafted image file that, when opened
in an application linked against libexif, could cause the application
to crash or, potentially, execute arbitrary code with the privileges
of the user running the application. (CVE-2012-2812, CVE-2012-2813,
CVE-2012-2814, CVE-2012-2836, CVE-2012-2837, CVE-2012-2840,
CVE-2012-2841)

Red Hat would like to thank Dan Fandrich for reporting these issues.
Upstream acknowledges Mateusz Jurczyk of the Google Security Team as
the original reporter of CVE-2012-2812, CVE-2012-2813, and
CVE-2012-2814; and Yunho Kim as the original reporter of CVE-2012-2836
and CVE-2012-2837.

Users of libexif are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. All running
applications linked against libexif must be restarted for the update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6005332"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb193e8f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libexif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libexif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libexif-0.6.21-1.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libexif-devel-0.6.21-1.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libexif-0.6.21-5.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libexif-devel-0.6.21-5.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
