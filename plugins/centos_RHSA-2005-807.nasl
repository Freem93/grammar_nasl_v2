#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:807 and 
# CentOS Errata and Security Advisory 2005:807 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21864);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-3185");
  script_osvdb_id(20011, 20012);
  script_xref(name:"RHSA", value:"2005:807");

  script_name(english:"CentOS 3 / 4 : curl (CESA-2005:807)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and
Dict servers, using any of the supported protocols.

A stack based buffer overflow bug was found in cURL's NTLM
authentication module. It is possible to execute arbitrary code on a
user's machine if the user can be tricked into connecting to a
malicious web server using NTLM authentication. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-3185 to this issue.

All users of curl are advised to upgrade to these updated packages,
which contain a backported patch that resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b8a6cfe"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012355.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57a53b9e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012363.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dec6a9a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012364.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39a8faba"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20324432"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02104d80"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"curl-7.10.6-7.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"curl-devel-7.10.6-7.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"curl-7.12.1-6.rhel4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"curl-devel-7.12.1-6.rhel4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
