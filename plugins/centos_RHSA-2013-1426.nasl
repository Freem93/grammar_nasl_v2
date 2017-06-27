#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1426 and 
# CentOS Errata and Security Advisory 2013:1426 respectively.
#

include("compat.inc");

if (description)
{
  script_id(70464);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-4396");
  script_bugtraq_id(62892);
  script_osvdb_id(98314);
  script_xref(name:"RHSA", value:"2013:1426");

  script_name(english:"CentOS 5 / 6 : xorg-x11-server (CESA-2013:1426)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-server packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

A use-after-free flaw was found in the way the X.Org server handled
ImageText requests. A malicious, authorized client could use this flaw
to crash the X.Org server or, potentially, execute arbitrary code with
root privileges. (CVE-2013-4396)

Red Hat would like to thank the X.Org security team for reporting this
issue. Upstream acknowledges Pedro Ribeiro as the original reporter.

All xorg-x11-server users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-October/019973.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad0d0f4f"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-October/000892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a46db145"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvnc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");
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
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xdmx-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xephyr-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xnest-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xorg-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xvfb-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-Xvnc-source-1.1.1-48.101.el5_10.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xorg-x11-server-sdk-1.1.1-48.101.el5_10.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xdmx-1.13.0-11.1.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xephyr-1.13.0-11.1.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xnest-1.13.0-11.1.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xorg-1.13.0-11.1.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xvfb-1.13.0-11.1.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-common-1.13.0-11.1.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-devel-1.13.0-11.1.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-source-1.13.0-11.1.el6.centos.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
