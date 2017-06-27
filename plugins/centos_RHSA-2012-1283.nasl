#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1283 and 
# CentOS Errata and Security Advisory 2012:1283 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62127);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:09:25 $");

  script_cve_id("CVE-2012-3535");
  script_bugtraq_id(55214);
  script_osvdb_id(84978);
  script_xref(name:"RHSA", value:"2012:1283");

  script_name(english:"CentOS 6 : openjpeg (CESA-2012:1283)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openjpeg packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

OpenJPEG is an open source library for reading and writing image files
in JPEG 2000 format.

It was found that OpenJPEG failed to sanity-check an image header
field before using it. A remote attacker could provide a specially
crafted image file that could cause an application linked against
OpenJPEG to crash or, possibly, execute arbitrary code.
(CVE-2012-3535)

This issue was discovered by Huzaifa Sidhpurwala of the Red Hat
Security Response Team.

Users of OpenJPEG should upgrade to these updated packages, which
contain a patch to correct this issue. All running applications using
OpenJPEG must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018885.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d074d25a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");
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
if (rpm_check(release:"CentOS-6", reference:"openjpeg-1.3-9.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openjpeg-devel-1.3-9.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openjpeg-libs-1.3-9.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
