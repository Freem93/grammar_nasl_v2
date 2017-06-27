#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1615 and 
# CentOS Errata and Security Advisory 2009:1615 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43807);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2009-2625");
  script_bugtraq_id(35958);
  script_osvdb_id(56984);
  script_xref(name:"RHSA", value:"2009:1615");

  script_name(english:"CentOS 5 : xerces-j2 (CESA-2009:1615)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xerces-j2 packages that fix a security issue are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The xerces-j2 packages provide the Apache Xerces2 Java Parser, a
high-performance XML parser. A Document Type Definition (DTD) defines
the legal syntax (and also which elements can be used) for certain
types of files, such as XML files.

A flaw was found in the way the Apache Xerces2 Java Parser processed
the SYSTEM identifier in DTDs. A remote attacker could provide a
specially crafted XML file, which once parsed by an application using
the Apache Xerces2 Java Parser, would lead to a denial of service
(application hang due to excessive CPU use). (CVE-2009-2625)

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. Applications using the Apache
Xerces2 Java Parser must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?121a7745"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016369.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f12283f0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xerces-j2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-javadoc-xni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"xerces-j2-2.7.1-7jpp.2.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xerces-j2-demo-2.7.1-7jpp.2.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xerces-j2-javadoc-apis-2.7.1-7jpp.2.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xerces-j2-javadoc-impl-2.7.1-7jpp.2.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xerces-j2-javadoc-other-2.7.1-7jpp.2.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xerces-j2-javadoc-xni-2.7.1-7jpp.2.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xerces-j2-scripts-2.7.1-7jpp.2.el5_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
