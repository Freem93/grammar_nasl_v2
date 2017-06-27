#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1804 and 
# CentOS Errata and Security Advisory 2013:1804 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71272);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2013-6629");
  script_bugtraq_id(63676);
  script_osvdb_id(99711);
  script_xref(name:"RHSA", value:"2013:1804");

  script_name(english:"CentOS 5 : libjpeg (CESA-2013:1804)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated libjpeg package that fixes one security issue is now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libjpeg package contains a library of functions for manipulating
JPEG images. It also contains simple client programs for accessing the
libjpeg functions.

An uninitialized memory read issue was found in the way libjpeg
decoded images with missing Start Of Scan (SOS) JPEG markers. A remote
attacker could create a specially crafted JPEG image that, when
decoded, could possibly lead to a disclosure of potentially sensitive
information. (CVE-2013-6629)

All libjpeg users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-December/020053.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9260d58e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libjpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
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
if (rpm_check(release:"CentOS-5", reference:"libjpeg-6b-38")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libjpeg-devel-6b-38")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
