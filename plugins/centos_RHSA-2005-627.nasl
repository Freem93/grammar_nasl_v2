#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:627 and 
# CentOS Errata and Security Advisory 2005:627 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21846);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2102", "CVE-2005-2103", "CVE-2005-2370");
  script_bugtraq_id(14531);
  script_osvdb_id(18126, 18668, 18669);
  script_xref(name:"RHSA", value:"2005:627");

  script_name(english:"CentOS 3 / 4 : gaim (CESA-2005:627)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gaim package that fixes multiple security issues is now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Gaim is an Internet Messaging client.

A heap based buffer overflow issue was discovered in the way Gaim
processes away messages. A remote attacker could send a specially
crafted away message to a Gaim user logged into AIM or ICQ that could
result in arbitrary code execution. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-2103
to this issue.

Daniel Atallah discovered a denial of service issue in Gaim. A remote
attacker could attempt to upload a file with a specially crafted name
to a user logged into AIM or ICQ, causing Gaim to crash. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2102 to this issue.

A denial of service bug was found in Gaim's Gadu Gadu protocol
handler. A remote attacker could send a specially crafted message to a
Gaim user logged into Gadu Gadu, causing Gaim to crash. Please note
that this issue only affects PPC and IBM S/390 systems running Gaim.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-2370 to this issue.

Users of gaim are advised to upgrade to this updated package, which
contains backported patches and is not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c14a458d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?771562b9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?826e03c1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?455f5e89"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af0cfbe4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012050.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e44524ab"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gaim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/21");
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
if (rpm_check(release:"CentOS-3", reference:"gaim-1.3.1-0.el3.3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gaim-1.3.1-0.el4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
