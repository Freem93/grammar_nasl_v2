#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0337 and 
# CentOS Errata and Security Advisory 2011:0337 respectively.
#

include("compat.inc");

if (description)
{
  script_id(52617);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2011-0762");
  script_bugtraq_id(46617);
  script_osvdb_id(73340);
  script_xref(name:"RHSA", value:"2011:0337");

  script_name(english:"CentOS 4 / 5 : vsftpd (CESA-2011:0337)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated vsftpd package that fixes one security issue is now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

vsftpd (Very Secure File Transfer Protocol (FTP) daemon) is a secure
FTP server for Linux, UNIX, and similar operating systems.

A flaw was discovered in the way vsftpd processed file name patterns.
An FTP user could use this flaw to cause the vsftpd process to use an
excessive amount of CPU time, when processing a request with a
specially crafted file name pattern. (CVE-2011-0762)

All vsftpd users should upgrade to this updated package, which
contains a backported patch to correct this issue. The vsftpd daemon
must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49d7311b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017402.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d2bcb31"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-March/017270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e4d71e7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-March/017271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e4c4da0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vsftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vsftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vsftpd-2.0.1-9.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vsftpd-2.0.1-9.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"vsftpd-2.0.5-16.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
