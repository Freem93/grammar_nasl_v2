#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0726 and 
# CentOS Errata and Security Advisory 2016:0726 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91020);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718");
  script_osvdb_id(137951, 137952, 137953, 137954, 137955);
  script_xref(name:"RHSA", value:"2016:0726");

  script_name(english:"CentOS 6 / 7 : ImageMagick (CESA-2016:0726) (ImageTragick)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ImageMagick is now available for Red Hat Enterprise
Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

Security Fix(es) :

* It was discovered that ImageMagick did not properly sanitize certain
input before passing it to the delegate functionality. A remote
attacker could create a specially crafted image that, when processed
by an application using ImageMagick or an unsuspecting user using the
ImageMagick utilities, would lead to arbitrary execution of shell
commands with the privileges of the user running the application.
(CVE-2016-3714)

* It was discovered that certain ImageMagick coders and
pseudo-protocols did not properly prevent security sensitive
operations when processing specially crafted images. A remote attacker
could create a specially crafted image that, when processed by an
application using ImageMagick or an unsuspecting user using the
ImageMagick utilities, would allow the attacker to delete, move, or
disclose the contents of arbitrary files. (CVE-2016-3715,
CVE-2016-3716, CVE-2016-3717)

* A server-side request forgery flaw was discovered in the way
ImageMagick processed certain images. A remote attacker could exploit
this flaw to mislead an application using ImageMagick or an
unsuspecting user using the ImageMagick utilities into, for example,
performing HTTP(S) requests or opening FTP sessions via specially
crafted images. (CVE-2016-3718)

Note: This update contains an updated /etc/ImageMagick/policy.xml file
that disables the EPHEMERAL, HTTPS, HTTP, URL, FTP, MVG, MSL, TEXT,
and LABEL coders. If you experience any problems after the update, it
may be necessary to manually adjust the policy.xml file to match your
requirements. Please take additional precautions to ensure that your
applications using the ImageMagick library do not process malicious or
untrusted files before doing so."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021865.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021866.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-c++-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-c++-devel-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-devel-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-doc-6.7.2.7-4.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-perl-6.7.2.7-4.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-c++-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-devel-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-doc-6.7.8.9-13.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-perl-6.7.8.9-13.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
