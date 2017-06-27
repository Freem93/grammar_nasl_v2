#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0066 and 
# CentOS Errata and Security Advisory 2007:0066 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24818);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2007-0456", "CVE-2007-0457", "CVE-2007-0458", "CVE-2007-0459");
  script_osvdb_id(33073, 33074, 33075, 33076);
  script_xref(name:"RHSA", value:"2007:0066");

  script_name(english:"CentOS 3 / 4 : wireshark (CESA-2007:0066)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Wireshark packages that fix various security vulnerabilities are
now available. Wireshark was previously known as Ethereal.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Wireshark is a program for monitoring network traffic.

Several denial of service bugs were found in Wireshark's LLT, IEEE
802.11, http, and tcp protocol dissectors. It was possible for
Wireshark to crash or stop responding if it read a malformed packet
off the network. (CVE-2007-0456, CVE-2007-0457, CVE-2007-0458,
CVE-2007-0459)

Users of Wireshark should upgrade to these updated packages containing
Wireshark version 0.99.5, which is not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013618.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fe1f740"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013619.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b402d4a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?262be912"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013621.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dda8ff5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013622.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?050f1dfc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013623.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?902bd418"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"wireshark-0.99.5-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"wireshark-gnome-0.99.5-EL3.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"wireshark-0.99.5-EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"wireshark-gnome-0.99.5-EL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
