#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1147 and 
# CentOS Errata and Security Advisory 2014:1147 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77508);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/14 00:10:14 $");

  script_cve_id("CVE-2014-3609");
  script_bugtraq_id(69453);
  script_xref(name:"RHSA", value:"2014:1147");

  script_name(english:"CentOS 7 : squid (CESA-2014:1147)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated squid packages that fix one security issue are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Squid is a high-performance proxy caching server for web clients,
supporting FTP, Gopher, and HTTP data objects.

A flaw was found in the way Squid handled malformed HTTP Range
headers. A remote attacker able to send HTTP requests to the Squid
proxy could use this flaw to crash Squid. (CVE-2014-3609)

Red Hat would like to thank the Squid project for reporting this
issue. Upstream acknowledges Matthew Daley as the original reporter.

All Squid users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing this update, the squid service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0293210"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid-sysvinit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"squid-3.3.8-12.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"squid-sysvinit-3.3.8-12.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
