#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0157 and 
# CentOS Errata and Security Advisory 2008:0157 respectively.
#

include("compat.inc");

if (description)
{
  script_id(31142);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/03/19 14:21:02 $");

  script_cve_id("CVE-2008-0882");
  script_bugtraq_id(27906);
  script_osvdb_id(42030);
  script_xref(name:"RHSA", value:"2008:0157");

  script_name(english:"CentOS 5 : cups (CESA-2008:0157)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix a security issue are now available for
Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems. The Internet Printing Protocol
(IPP) is a standard network protocol for remote printing, as well as
managing print jobs.

A flaw was found in the way CUPS handles the addition and removal of
remote shared printers via IPP. A remote attacker could send malicious
UDP IPP packets causing the CUPS daemon to crash. (CVE-2008-0882)

Note: the default configuration of CUPS on Red Hat Enterprise Linux 5
will only accept requests of this type from the local subnet. This
issue did not affect the versions of CUPS as shipped with Red Hat
Enterprise Linux 3 or 4.

All cups users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014704.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67311c67"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014705.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b6d49af"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"cups-1.2.4-11.14.el5_1.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.2.4-11.14.el5_1.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.2.4-11.14.el5_1.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.2.4-11.14.el5_1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
