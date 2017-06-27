#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0541 and 
# CentOS Errata and Security Advisory 2006:0541 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21998);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-2453", "CVE-2006-2480");
  script_bugtraq_id(18078, 18166);
  script_osvdb_id(25699, 25840);
  script_xref(name:"RHSA", value:"2006:0541");

  script_name(english:"CentOS 4 : dia (CESA-2006:0541)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Dia packages that fix several buffer overflow bugs are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Dia drawing program is designed to draw various types of diagrams.

Several format string flaws were found in the way dia displays certain
messages. If an attacker is able to trick a Dia user into opening a
carefully crafted file, it may be possible to execute arbitrary code
as the user running Dia. (CVE-2006-2453, CVE-2006-2480)

Users of Dia should update to these erratum packages, which contain
backported patches and are not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012931.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad0fc94b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012938.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8732cab7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012939.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4ea14d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dia package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dia");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/05");
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
if (rpm_check(release:"CentOS-4", reference:"dia-0.94-5.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
