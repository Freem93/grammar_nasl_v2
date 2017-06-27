#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0981 and 
# CentOS Errata and Security Advisory 2008:0981 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35263);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-3656", "CVE-2008-4310");
  script_bugtraq_id(30644);
  script_xref(name:"RHSA", value:"2008:0981");

  script_name(english:"CentOS 4 / 5 : ruby (CESA-2008:0981)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix a security issue are now available for
Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

Vincent Danen reported, that Red Hat Security Advisory RHSA-2008:0897
did not properly address a denial of service flaw in the WEBrick (Ruby
HTTP server toolkit), known as CVE-2008-3656. This flaw allowed a
remote attacker to send a specially crafted HTTP request to a WEBrick
server that would cause the server to use excessive CPU time. This
update properly addresses this flaw. (CVE-2008-4310)

All Ruby users should upgrade to these updated packages, which contain
a correct patch that resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c10c00e0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015473.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eabd5518"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015474.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab68fc7a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fbcb0a9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-December/015515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e96b1e3d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"irb-1.8.1-7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-1.8.1-7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-devel-1.8.1-7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-docs-1.8.1-7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-libs-1.8.1-7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-mode-1.8.1-7.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-tcltk-1.8.1-7.el4_7.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ruby-1.8.5-5.el5_2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-devel-1.8.5-5.el5_2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-docs-1.8.5-5.el5_2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-irb-1.8.5-5.el5_2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-libs-1.8.5-5.el5_2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-mode-1.8.5-5.el5_2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-rdoc-1.8.5-5.el5_2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-ri-1.8.5-5.el5_2.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-tcltk-1.8.5-5.el5_2.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
