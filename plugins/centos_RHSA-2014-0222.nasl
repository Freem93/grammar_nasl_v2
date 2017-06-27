#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0222 and 
# CentOS Errata and Security Advisory 2014:0222 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72732);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 14:54:14 $");

  script_cve_id("CVE-2010-2596", "CVE-2013-1960", "CVE-2013-1961", "CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_bugtraq_id(41295, 59607, 59609, 61695, 61849, 62019, 62082);
  script_osvdb_id(92986, 92987, 96203, 96204, 96205, 96206, 96207, 96649, 96783);
  script_xref(name:"RHSA", value:"2014:0222");

  script_name(english:"CentOS 6 : libtiff (CESA-2014:0222)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtiff packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

A heap-based buffer overflow and a use-after-free flaw were found in
the tiff2pdf tool. An attacker could use these flaws to create a
specially crafted TIFF file that would cause tiff2pdf to crash or,
possibly, execute arbitrary code. (CVE-2013-1960, CVE-2013-4232)

Multiple buffer overflow flaws were found in the gif2tiff tool. An
attacker could use these flaws to create a specially crafted GIF file
that could cause gif2tiff to crash or, possibly, execute arbitrary
code. (CVE-2013-4231, CVE-2013-4243, CVE-2013-4244)

A flaw was found in the way libtiff handled OJPEG-encoded TIFF images.
An attacker could use this flaw to create a specially crafted TIFF
file that would cause an application using libtiff to crash.
(CVE-2010-2596)

Multiple buffer overflow flaws were found in the tiff2pdf tool. An
attacker could use these flaws to create a specially crafted TIFF file
that would cause tiff2pdf to crash. (CVE-2013-1961)

Red Hat would like to thank Emmanuel Bouillon of NCI Agency for
reporting CVE-2013-1960 and CVE-2013-1961. The CVE-2013-4243 issue was
discovered by Murray McAllister of the Red Hat Security Response Team,
and the CVE-2013-4244 issue was discovered by Huzaifa Sidhpurwala of
the Red Hat Security Response Team.

All libtiff users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
applications linked against libtiff must be restarted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-February/020181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7464c304"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libtiff-3.9.4-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtiff-devel-3.9.4-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtiff-static-3.9.4-10.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
