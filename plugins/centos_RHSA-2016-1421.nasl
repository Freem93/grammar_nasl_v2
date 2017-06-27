#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1421 and 
# CentOS Errata and Security Advisory 2016:1421 respectively.
#

include("compat.inc");

if (description)
{
  script_id(92378);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/01/16 16:05:32 $");

  script_cve_id("CVE-2016-5387");
  script_osvdb_id(141669);
  script_xref(name:"RHSA", value:"2016:1421");
  script_xref(name:"IAVA", value:"2017-A-0010");

  script_name(english:"CentOS 5 / 6 : httpd (CESA-2016:1421) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for httpd is now available for Red Hat Enterprise Linux 5
and Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

Security Fix(es) :

* It was discovered that httpd used the value of the Proxy header from
HTTP requests to initialize the HTTP_PROXY environment variable for
CGI scripts, which in turn was incorrectly used by certain HTTP client
implementations to configure the proxy for outgoing HTTP requests. A
remote attacker could possibly use this flaw to redirect HTTP requests
performed by a CGI script to an attacker-controlled proxy via a
malicious HTTP request. (CVE-2016-5387)

Note: After this update, httpd will no longer pass the value of the
Proxy request header to scripts via the HTTP_PROXY environment
variable.

Red Hat would like to thank Scott Geary (VendHQ) for reporting this
issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-July/021978.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33c410da"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-July/021980.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dc770b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-92.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-92.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-92.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-92.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"httpd-2.2.15-54.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-devel-2.2.15-54.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-manual-2.2.15-54.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-tools-2.2.15-54.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mod_ssl-2.2.15-54.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
