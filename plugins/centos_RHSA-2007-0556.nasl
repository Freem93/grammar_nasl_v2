#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0556 and 
# CentOS Errata and Security Advisory 2007:0556 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25579);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2006-5752", "CVE-2007-1863", "CVE-2007-3304");
  script_bugtraq_id(24215, 24645, 24649);
  script_osvdb_id(37050, 37052, 38939);
  script_xref(name:"RHSA", value:"2007:0556");

  script_name(english:"CentOS 5 : httpd (CESA-2007:0556)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that correct three security issues are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

The Apache HTTP Server did not verify that a process was an Apache
child process before sending it signals. A local attacker with the
ability to run scripts on the Apache HTTP Server could manipulate the
scoreboard and cause arbitrary processes to be terminated which could
lead to a denial of service (CVE-2007-3304). This issue is not
exploitable on Red Hat Enterprise Linux 5 if using the default SELinux
targeted policy.

A flaw was found in the Apache HTTP Server mod_status module. On sites
where the server-status page is publicly accessible and ExtendedStatus
is enabled this could lead to a cross-site scripting attack. On Red
Hat Enterprise Linux the server-status page is not enabled by default
and it is best practice to not make this publicly available.
(CVE-2006-5752)

A bug was found in the Apache HTTP Server mod_cache module. On sites
where caching is enabled, a remote attacker could send a carefully
crafted request that would cause the Apache child process handling
that request to crash. This could lead to a denial of service if using
a threaded Multi-Processing Module. (CVE-2007-1863)

Users of httpd should upgrade to these updated packages, which contain
backported patches to correct these issues. Users should restart
Apache after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013990.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20453457"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013991.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85675eb8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-7.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-7.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-7.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-7.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
