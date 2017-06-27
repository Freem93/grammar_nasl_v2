#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:640 and 
# CentOS Errata and Security Advisory 2005:640 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21847);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2335");
  script_bugtraq_id(14349);
  script_osvdb_id(18174);
  script_xref(name:"RHSA", value:"2005:640");

  script_name(english:"CentOS 3 / 4 : fetchmail (CESA-2005:640)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated fetchmail packages that fix a security flaw are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Fetchmail is a remote mail retrieval and forwarding utility.

A buffer overflow was discovered in fetchmail's POP3 client. A
malicious server could cause send a carefully crafted message UID and
cause fetchmail to crash or potentially execute arbitrary code as the
user running fetchmail. The Common Vulnerabilities and Exposures
project assigned the name CVE-2005-2335 to this issue.

Users of fetchmail should update to this erratum package which
contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011973.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f568e80e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011974.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00ed8600"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011975.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99665102"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc56ca3a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011986.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f1182a8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011990.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34b855e8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fetchmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/20");
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
if (rpm_check(release:"CentOS-3", reference:"fetchmail-6.2.0-3.el3.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"fetchmail-6.2.5-6.el4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
