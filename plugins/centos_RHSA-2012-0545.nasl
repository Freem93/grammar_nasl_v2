#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0545 and 
# CentOS Errata and Security Advisory 2012:0545 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59020);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:09:24 $");

  script_cve_id("CVE-2012-0247", "CVE-2012-0248", "CVE-2012-0260");
  script_bugtraq_id(51957, 52898);
  script_osvdb_id(79003, 79004, 81022);
  script_xref(name:"RHSA", value:"2012:0545");

  script_name(english:"CentOS 5 : ImageMagick (CESA-2012:0545)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that fix three security issues and one
bug are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

A flaw was found in the way ImageMagick processed images with
malformed Exchangeable image file format (Exif) metadata. An attacker
could create a specially crafted image file that, when opened by a
victim, would cause ImageMagick to crash or, potentially, execute
arbitrary code. (CVE-2012-0247)

A denial of service flaw was found in the way ImageMagick processed
images with malformed Exif metadata. An attacker could create a
specially crafted image file that, when opened by a victim, could
cause ImageMagick to enter an infinite loop. (CVE-2012-0248)

A denial of service flaw was found in the way ImageMagick decoded
certain JPEG images. A remote attacker could provide a JPEG image with
specially crafted sequences of RST0 up to RST7 restart markers (used
to indicate the input stream to be corrupted), which once processed by
ImageMagick, would cause it to consume excessive amounts of memory and
CPU time. (CVE-2012-0260)

Red Hat would like to thank CERT-FI for reporting CVE-2012-0260.
CERT-FI acknowledges Aleksis Kauppinen, Joonas Kuorilehto, Tuomas
Parttimaa and Lasse Ylivainio of Codenomicon's CROSS project as the
original reporters.

This update also fixes the following bug :

* The fix for Red Hat Bugzilla bug 694922, provided by the
RHSA-2012:0301 ImageMagick update, introduced a regression. Attempting
to use the 'convert' utility to convert a PostScript document could
fail with a '/undefinedfilename' error. With this update, conversion
works as expected. (BZ#804546)

Users of ImageMagick are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
instances of ImageMagick must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2012-May/018612.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/08");
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
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-6.2.8.0-15.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-c++-6.2.8.0-15.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-c++-devel-6.2.8.0-15.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-devel-6.2.8.0-15.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ImageMagick-perl-6.2.8.0-15.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
