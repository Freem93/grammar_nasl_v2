#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1075 and 
# CentOS Errata and Security Advisory 2009:1075 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43753);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2008-1678", "CVE-2009-1195");
  script_bugtraq_id(31692);
  script_osvdb_id(47810, 54733);
  script_xref(name:"RHSA", value:"2009:1075");

  script_name(english:"CentOS 5 : httpd (CESA-2009:1075)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular and freely-available Web server.

A flaw was found in the handling of compression structures between
mod_ssl and OpenSSL. If too many connections were opened in a short
period of time, all system memory and swap space would be consumed by
httpd, negatively impacting other processes, or causing a system
crash. (CVE-2008-1678)

Note: The CVE-2008-1678 issue did not affect Red Hat Enterprise Linux
5 prior to 5.3. The problem was introduced via the RHBA-2009:0181
errata in Red Hat Enterprise Linux 5.3, which upgraded OpenSSL to the
newer 0.9.8e version.

A flaw was found in the handling of the 'Options' and 'AllowOverride'
directives. In configurations using the 'AllowOverride' directive with
certain 'Options=' arguments, local users were not restricted from
executing commands from a Server-Side-Include script as intended.
(CVE-2009-1195)

All httpd users should upgrade to these updated packages, which
contain backported patches to resolve these issues. Users must restart
httpd for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015953.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015954.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-22.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-22.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-22.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-22.el5.centos.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
