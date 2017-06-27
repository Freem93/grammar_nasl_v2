#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0957 and 
# CentOS Errata and Security Advisory 2007:0957 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43656);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/28 23:45:05 $");

  script_cve_id("CVE-2007-4924");
  script_osvdb_id(41637);
  script_xref(name:"RHSA", value:"2007:0957");

  script_name(english:"CentOS 5 : opal (CESA-2007:0957)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated opal packages that fix a security issue are now available for
Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Open Phone Abstraction Library (opal) is implementation of various
telephony and video communication protocols for use over packet based
networks.

In Red Hat Enterprise Linux 5, the Ekiga application uses opal.

A flaw was discovered in the way opal handled certain Session
Initiation Protocol (SIP) packets. An attacker could use this flaw to
crash an application, such as Ekiga, which is linked with opal.
(CVE-2007-4924)

Users should upgrade to these updated opal packages which contain a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014290.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc8bbee2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbce9caf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opal packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:opal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:opal-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"opal-2.2.2-1.1.0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"opal-devel-2.2.2-1.1.0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
