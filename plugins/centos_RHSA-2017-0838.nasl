#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0838 and 
# CentOS Errata and Security Advisory 2017:0838 respectively.
#

include("compat.inc");

if (description)
{
  script_id(99041);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2013-6045", "CVE-2016-5139", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-7163", "CVE-2016-9573", "CVE-2016-9675");
  script_osvdb_id(100638, 142530, 142663, 142664, 143027, 143652, 146612);
  script_xref(name:"RHSA", value:"2017:0838");

  script_name(english:"CentOS 7 : openjpeg (CESA-2017:0838)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for openjpeg is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenJPEG is an open source library for reading and writing image files
in JPEG2000 format.

Security Fix(es) :

* Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in OpenJPEG. A specially crafted JPEG2000 image
could cause an application using OpenJPEG to crash or, potentially,
execute arbitrary code. (CVE-2016-5139, CVE-2016-5158, CVE-2016-5159,
CVE-2016-7163)

* An out-of-bounds read vulnerability was found in OpenJPEG, in the
j2k_to_image tool. Converting a specially crafted JPEG2000 file to
another format could cause the application to crash or, potentially,
disclose some data from the heap. (CVE-2016-9573)

* A heap-based buffer overflow vulnerability was found in OpenJPEG. A
specially crafted JPEG2000 image, when read by an application using
OpenJPEG, could cause the application to crash or, potentially,
execute arbitrary code. (CVE-2016-9675)

Red Hat would like to thank Liu Bingchang (IIE) for reporting
CVE-2016-9573. The CVE-2016-9675 issue was discovered by Doran Moppert
(Red Hat Product Security)."
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-March/022349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe8914e9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openjpeg-1.5.1-16.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openjpeg-devel-1.5.1-16.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openjpeg-libs-1.5.1-16.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
