#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0154 and 
# CentOS Errata and Security Advisory 2011:0154 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53413);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:43:08 $");

  script_cve_id("CVE-2010-4267");
  script_osvdb_id(70498);
  script_xref(name:"RHSA", value:"2011:0154");

  script_name(english:"CentOS 5 : hplip / hplip3 (CESA-2011:0154)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hplip packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Hewlett-Packard Linux Imaging and Printing (HPLIP) provides drivers
for Hewlett-Packard printers and multifunction peripherals, and tools
for installing, using, and configuring them.

A flaw was found in the way certain HPLIP tools discovered devices
using the SNMP protocol. If a user ran certain HPLIP tools that search
for supported devices using SNMP, and a malicious user is able to send
specially crafted SNMP responses, it could cause those HPLIP tools to
crash or, possibly, execute arbitrary code with the privileges of the
user running them. (CVE-2010-4267)

Red Hat would like to thank Sebastian Krahmer of the SuSE Security
Team for reporting this issue.

Users of hplip should upgrade to these updated packages, which contain
a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fadaf058"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40cc1af5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0049c445"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017345.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbc8bd97"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip and / or hplip3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip3-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsane-hpaio3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"hpijs-1.6.7-6.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hpijs3-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip-1.6.7-6.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip3-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip3-common-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip3-gui-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip3-libs-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsane-hpaio-1.6.7-6.el5_6.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsane-hpaio3-3.9.8-11.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
