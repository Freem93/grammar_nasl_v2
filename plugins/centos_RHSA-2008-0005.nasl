#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0005 and 
# CentOS Errata and Security Advisory 2008:0005 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29966);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-3847", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2008-0005");
  script_bugtraq_id(25489, 25653, 26838, 27234, 27237);
  script_osvdb_id(40262, 42214);
  script_xref(name:"RHSA", value:"2008:0005");

  script_name(english:"CentOS 3 : httpd (CESA-2008:0005)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that fix several security issues are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A flaw was found in the mod_imap module. On sites where mod_imap was
enabled and an imagemap file was publicly available, a cross-site
scripting attack was possible. (CVE-2007-5000)

A flaw was found in the mod_autoindex module. On sites where directory
listings are used, and the 'AddDefaultCharset' directive has been
removed from the configuration, a cross-site scripting attack was
possible against Web browsers which did not correctly derive the
response character set following the rules in RFC 2616.
(CVE-2007-4465)

A flaw was found in the mod_proxy module. On sites where a reverse
proxy is configured, a remote attacker could send a carefully crafted
request that would cause the Apache child process handling that
request to crash. On sites where a forward proxy is configured, an
attacker could cause a similar crash if a user could be persuaded to
visit a malicious site using the proxy. This could lead to a denial of
service if using a threaded Multi-Processing Module. (CVE-2007-3847)

A flaw was found in the mod_status module. On sites where mod_status
was enabled and the status pages were publicly available, a cross-site
scripting attack was possible. (CVE-2007-6388)

A flaw was found in the mod_proxy_ftp module. On sites where
mod_proxy_ftp was enabled and a forward proxy was configured, a
cross-site scripting attack was possible against Web browsers which
did not correctly derive the response character set following the
rules in RFC 2616. (CVE-2008-0005)

Users of Apache httpd should upgrade to these updated packages, which
contain backported patches to resolve these issues. Users should
restart httpd after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b77f7a83"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014606.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa06dd6a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014609.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b3e64a0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/15");
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
if (rpm_check(release:"CentOS-3", reference:"httpd-2.0.46-70.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"httpd-devel-2.0.46-70.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_ssl-2.0.46-70.ent.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
