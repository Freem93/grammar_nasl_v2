#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:340 and 
# CentOS Errata and Security Advisory 2005:340 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21805);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0490");
  script_osvdb_id(14033, 14034);
  script_xref(name:"RHSA", value:"2005:340");

  script_name(english:"CentOS 3 / 4 : curl (CESA-2005:340)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and
Dict servers, using any of the supported protocols. cURL is designed
to work without user interaction or any kind of interactivity.

Multiple buffer overflow bugs were found in the way curl processes
base64 encoded replies. If a victim can be tricked into visiting a URL
with curl, a malicious web server could execute arbitrary code on a
victim's machine. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0490 to this issue.

All users of curl are advised to upgrade to these updated packages,
which contain backported fixes for these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee886191"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011532.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6851472"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cba7089b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011542.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20a8823e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011545.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fdc0ae2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/21");
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
if (rpm_check(release:"CentOS-3", reference:"curl-7.10.6-6.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"curl-devel-7.10.6-6.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"curl-7.12.1-5.rhel4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"curl-devel-7.12.1-5.rhel4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
