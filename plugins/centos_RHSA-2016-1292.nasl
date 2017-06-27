#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1292 and 
# CentOS Errata and Security Advisory 2016:1292 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91786);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4449");
  script_osvdb_id(130651, 130653, 134833, 136114, 136194, 137962, 138566, 138567, 138568, 138569, 138570, 138572, 138926, 138928, 138966);
  script_xref(name:"RHSA", value:"2016:1292");

  script_name(english:"CentOS 6 / 7 : libxml2 (CESA-2016:1292)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libxml2 is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

Security Fix(es) :

A heap-based buffer overflow flaw was found in the way libxml2 parsed
certain crafted XML input. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash or execute arbitrary
code with the permissions of the user running the application.
(CVE-2016-1834, CVE-2016-1840)

Multiple denial of service flaws were found in libxml2. A remote
attacker could provide a specially crafted XML file that, when
processed by an application using libxml2, could cause that
application to crash. (CVE-2016-1762, CVE-2016-1833, CVE-2016-1835,
CVE-2016-1836, CVE-2016-1837, CVE-2016-1838, CVE-2016-1839,
CVE-2016-3627, CVE-2016-3705, CVE-2016-4447, CVE-2016-4448,
CVE-2016-4449)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-June/021917.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02d158f1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-June/021929.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b3b689b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
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
if (rpm_check(release:"CentOS-6", reference:"libxml2-2.7.6-21.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-devel-2.7.6-21.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-python-2.7.6-21.el6_8.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-static-2.7.6-21.el6_8.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxml2-2.9.1-6.el7_2.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxml2-devel-2.9.1-6.el7_2.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxml2-python-2.9.1-6.el7_2.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxml2-static-2.9.1-6.el7_2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
