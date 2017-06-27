#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0533 and 
# CentOS Errata and Security Advisory 2007:0533 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25613);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2006-5752", "CVE-2007-1863");
  script_bugtraq_id(24645, 24649);
  script_osvdb_id(37052);
  script_xref(name:"RHSA", value:"2007:0533");

  script_name(english:"CentOS 3 : httpd (CESA-2007:0533)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that correct two security issues and two
bugs are now available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A flaw was found in the Apache HTTP Server mod_status module. On sites
where the server-status page is publicly accessible and ExtendedStatus
is enabled this could lead to a cross-site scripting attack. On Red
Hat Enterprise Linux the server-status page is not enabled by default
and it is best practice to not make this publicly available.
(CVE-2006-5752)

A flaw was found in the Apache HTTP Server mod_cache module. On sites
where caching is enabled, a remote attacker could send a carefully
crafted request that would cause the Apache child process handling
that request to crash. This could lead to a denial of service if using
a threaded Multi-Processing Module. (CVE-2007-1863)

In addition, two bugs were fixed :

* when the ProxyErrorOverride directive was enabled, responses with
3xx status-codes would be overriden at the proxy. This has been
changed so that only 4xx and 5xx responses are overriden.

* the 'ProxyTimeout' directive was not inherited across virtual host
definitions.

Users of httpd should upgrade to these updated packages, which contain
backported patches to correct these issues. Users should restart
Apache after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e100cde"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013993.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c16de126"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/014002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1972cde"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/21");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"httpd-2.0.46-67.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"httpd-devel-2.0.46-67.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_ssl-2.0.46-67.ent.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
