#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0544. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59028);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2010-4167", "CVE-2012-0247", "CVE-2012-0248", "CVE-2012-0259", "CVE-2012-0260", "CVE-2012-1798");
  script_bugtraq_id(45044, 51957, 52898);
  script_osvdb_id(69445, 79003, 79004, 81021, 81022, 81023);
  script_xref(name:"RHSA", value:"2012:0544");

  script_name(english:"RHEL 6 : ImageMagick (RHSA-2012:0544)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

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

It was found that ImageMagick utilities tried to load ImageMagick
configuration files from the current working directory. If a user ran
an ImageMagick utility in an attacker-controlled directory containing
a specially crafted ImageMagick configuration file, it could cause the
utility to execute arbitrary code. (CVE-2010-4167)

An integer overflow flaw was found in the way ImageMagick processed
certain Exif tags with a large components count. An attacker could
create a specially crafted image file that, when opened by a victim,
could cause ImageMagick to access invalid memory and crash.
(CVE-2012-0259)

A denial of service flaw was found in the way ImageMagick decoded
certain JPEG images. A remote attacker could provide a JPEG image with
specially crafted sequences of RST0 up to RST7 restart markers (used
to indicate the input stream to be corrupted), which once processed by
ImageMagick, would cause it to consume excessive amounts of memory and
CPU time. (CVE-2012-0260)

An out-of-bounds buffer read flaw was found in the way ImageMagick
processed certain TIFF image files. A remote attacker could provide a
TIFF image with a specially crafted Exif IFD value (the set of tags
for recording Exif-specific attribute information), which once opened
by ImageMagick, would cause it to crash. (CVE-2012-1798)

Red Hat would like to thank CERT-FI for reporting CVE-2012-0259,
CVE-2012-0260, and CVE-2012-1798. CERT-FI acknowledges Aleksis
Kauppinen, Joonas Kuorilehto, Tuomas Parttimaa and Lasse Ylivainio of
Codenomicon's CROSS project as the original reporters.

Users of ImageMagick are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
instances of ImageMagick must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0247.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0248.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0259.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0260.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0544.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0544";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", reference:"ImageMagick-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ImageMagick-c++-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ImageMagick-c++-devel-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ImageMagick-debuginfo-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ImageMagick-devel-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ImageMagick-doc-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ImageMagick-doc-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ImageMagick-doc-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ImageMagick-perl-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ImageMagick-perl-6.5.4.7-6.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ImageMagick-perl-6.5.4.7-6.el6_2")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
  }
}
