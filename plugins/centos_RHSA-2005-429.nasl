#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:429 and 
# CentOS Errata and Security Advisory 2005:429 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21825);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1261", "CVE-2005-1262");
  script_osvdb_id(13923, 16347, 16348);
  script_xref(name:"RHSA", value:"2005:429");

  script_name(english:"CentOS 3 / 4 : gaim (CESA-2005:429)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gaim package that fixes two security issues is now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The Gaim application is a multi-protocol instant messaging client.

A stack based buffer overflow bug was found in the way gaim processes
a message containing a URL. A remote attacker could send a carefully
crafted message resulting in the execution of arbitrary code on a
victim's machine. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1261 to this issue.

A bug was found in the way gaim handles malformed MSN messages. A
remote attacker could send a carefully crafted MSN message causing
gaim to crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1262 to this issue.

Users of Gaim are advised to upgrade to this updated package which
contains backported patches and is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011639.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011640.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011641.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011652.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011653.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gaim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/17");
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
if (rpm_check(release:"CentOS-3", reference:"gaim-1.2.1-6.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gaim-1.2.1-6.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
