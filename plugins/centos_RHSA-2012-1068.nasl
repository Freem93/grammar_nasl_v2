#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1068 and 
# CentOS Errata and Security Advisory 2012:1068 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59960);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/03 14:54:57 $");

  script_cve_id("CVE-2009-5030", "CVE-2012-3358");
  script_bugtraq_id(53012, 54373);
  script_osvdb_id(81343, 83741);
  script_xref(name:"RHSA", value:"2012:1068");

  script_name(english:"CentOS 6 : openjpeg (CESA-2012:1068)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openjpeg packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenJPEG is an open source library for reading and writing image files
in JPEG 2000 format.

An input validation flaw, leading to a heap-based buffer overflow, was
found in the way OpenJPEG handled the tile number and size in an image
tile header. A remote attacker could provide a specially crafted image
file that, when decoded using an application linked against OpenJPEG,
would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2012-3358)

OpenJPEG allocated insufficient memory when encoding JPEG 2000 files
from input images that have certain color depths. A remote attacker
could provide a specially crafted image file that, when opened in an
application linked against OpenJPEG (such as image_to_j2k), would
cause the application to crash or, potentially, execute arbitrary code
with the privileges of the user running the application.
(CVE-2009-5030)

Users of OpenJPEG should upgrade to these updated packages, which
contain patches to correct these issues. All running applications
using OpenJPEG must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018732.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5153e041"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"openjpeg-1.3-8.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openjpeg-devel-1.3-8.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openjpeg-libs-1.3-8.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
