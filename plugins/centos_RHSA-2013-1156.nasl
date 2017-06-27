#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1156 and 
# CentOS Errata and Security Advisory 2013:1156 respectively.
#

include("compat.inc");

if (description)
{
  script_id(69336);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-1896");
  script_bugtraq_id(61129);
  script_osvdb_id(95498);
  script_xref(name:"RHSA", value:"2013:1156");

  script_name(english:"CentOS 5 / 6 : httpd (CESA-2013:1156)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Apache HTTP Server is a popular web server.

A flaw was found in the way the mod_dav module of the Apache HTTP
Server handled merge requests. An attacker could use this flaw to send
a crafted merge request that contains URIs that are not configured for
DAV, causing the httpd child process to crash. (CVE-2013-1896)

All httpd users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, the httpd daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-August/019902.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02e7354c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-August/019903.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76273bf3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");
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
if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-82.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-82.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-82.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-82.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"httpd-2.2.15-29.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-devel-2.2.15-29.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-manual-2.2.15-29.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-tools-2.2.15-29.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mod_ssl-2.2.15-29.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
