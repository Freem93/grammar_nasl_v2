#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0747 and 
# CentOS Errata and Security Advisory 2007:0747 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67056);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/03 10:41:58 $");

  script_cve_id("CVE-2007-3847");
  script_bugtraq_id(25489);
  script_xref(name:"RHSA", value:"2007:0747");

  script_name(english:"CentOS 4 : httpd (CESA-2007:0747)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix a security issue, various bugs, and
add enhancements are now available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular and freely-available Web server.

A flaw was found in the Apache HTTP Server mod_proxy module. On sites
where a reverse proxy is configured, a remote attacker could send a
carefully crafted request that would cause the Apache child process
handling that request to crash. On sites where a forward proxy is
configured, an attacker could cause a similar crash if a user could be
persuaded to visit a malicious site using the proxy. This could lead
to a denial of service if using a threaded Multi-Processing Module.
(CVE-2007-3847)

As well, these updated packages fix the following bugs :

* the default '/etc/logrotate.d/httpd' script incorrectly invoked the
kill command, instead of using the '/sbin/service httpd restart'
command. If you configured the httpd PID to be in a location other
than '/var/run/httpd.pid', the httpd logs failed to be rotated. This
has been resolved in these updated packages.

* Set-Cookie headers with a status code of 3xx are not forwarded to
clients when the 'ProxyErrorOverride' directive is enabled. These
responses are overridden at the proxy. Only the responses with status
codes of 4xx and 5xx are overridden in these updated packages.

* mod_proxy did not correctly handle percent-encoded characters (ie
%20) when configured as a reverse proxy.

* invalid HTTP status codes could be logged if output filters returned
errors.

* the 'ProxyTimeout' directive was not inherited across virtual host
definitions.

* in some cases the Content-Length header was dropped from HEAD
responses. This resulted in certain sites not working correctly with
mod_proxy, such as www.windowsupdate.com.

This update adds the following enhancements :

* a new configuration option has been added, 'ServerTokens
Full-Release', which adds the package release to the server version
string, which is returned in the 'Server' response header.

* a new module has been added, mod_version, which allows configuration
files to be written containing sections, which are evaluated only if
the version of httpd used matches a specified condition.

Users of httpd are advised to upgrade to these updated packages, which
resolve these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e02489b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"httpd-2.0.52-38.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"httpd-devel-2.0.52-38.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"httpd-manual-2.0.52-38.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"httpd-suexec-2.0.52-38.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mod_ssl-2.0.52-38.ent.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
