#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0002 and 
# CentOS Errata and Security Advisory 2010:0002 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43624);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2009-3720");
  script_bugtraq_id(36097);
  script_osvdb_id(59737);
  script_xref(name:"RHSA", value:"2010:0002");

  script_name(english:"CentOS 4 / 5 : PyXML (CESA-2010:0002)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated PyXML package that fixes one security issue is now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PyXML provides XML libraries for Python. The distribution contains a
validating XML parser, an implementation of the SAX and DOM
programming interfaces, and an interface to the Expat parser.

A buffer over-read flaw was found in the way PyXML's Expat parser
handled malformed UTF-8 sequences when processing XML files. A
specially crafted XML file could cause Python applications using
PyXML's Expat parser to crash while parsing the file. (CVE-2009-3720)

This update makes PyXML use the system Expat library rather than its
own internal copy; therefore, users must install the RHSA-2009:1625
expat update together with this PyXML update to resolve the
CVE-2009-3720 issue.

All PyXML users should upgrade to this updated package, which changes
PyXML to use the system Expat library. After installing this update
along with RHSA-2009:1625, applications using the PyXML library must
be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016407.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6425525f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016408.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35e0af79"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dec69083"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d374a97b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pyxml package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:PyXML");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"PyXML-0.8.3-6.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"PyXML-0.8.3-6.el4_8.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"PyXML-0.8.4-4.el5_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
