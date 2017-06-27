#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0008 and 
# CentOS Errata and Security Advisory 2008:0008 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43666);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/30 15:10:02 $");

  script_cve_id("CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2007-6421", "CVE-2007-6422", "CVE-2008-0005");
  script_bugtraq_id(25653, 26838, 27234, 27236, 27237);
  script_osvdb_id(40262, 40263, 40264, 42214);
  script_xref(name:"RHSA", value:"2008:0008");

  script_name(english:"CentOS 5 : httpd (CESA-2008:0008)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that fix several security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A flaw was found in the mod_imagemap module. On sites where
mod_imagemap was enabled and an imagemap file was publicly available,
a cross-site scripting attack was possible. (CVE-2007-5000)

A flaw was found in the mod_autoindex module. On sites where directory
listings are used, and the 'AddDefaultCharset' directive has been
removed from the configuration, a cross-site scripting attack might
have been possible against Web browsers which do not correctly derive
the response character set following the rules in RFC 2616.
(CVE-2007-4465)

A flaw was found in the mod_status module. On sites where mod_status
was enabled and the status pages were publicly available, a cross-site
scripting attack was possible. (CVE-2007-6388)

A flaw was found in the mod_proxy_balancer module. On sites where
mod_proxy_balancer was enabled, a cross-site scripting attack against
an authorized user was possible. (CVE-2007-6421)

A flaw was found in the mod_proxy_balancer module. On sites where
mod_proxy_balancer was enabled, an authorized user could send a
carefully crafted request that would cause the Apache child process
handling that request to crash. This could lead to a denial of service
if using a threaded Multi-Processing Module. (CVE-2007-6422)

A flaw was found in the mod_proxy_ftp module. On sites where
mod_proxy_ftp was enabled and a forward proxy was configured, a
cross-site scripting attack was possible against Web browsers which do
not correctly derive the response character set following the rules in
RFC 2616. (CVE-2008-0005)

Users of Apache httpd should upgrade to these updated packages, which
contain backported patches to resolve these issues. Users should
restart httpd after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014614.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72637a09"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014615.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ce75799"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-11.el5_1.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-11.el5_1.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-11.el5_1.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-11.el5_1.centos.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
