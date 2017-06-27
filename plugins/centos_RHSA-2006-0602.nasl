#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0602 and 
# CentOS Errata and Security Advisory 2006:0602 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22238);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-3627", "CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632");
  script_bugtraq_id(19051);
  script_osvdb_id(27360, 27361, 27362, 27363, 27364, 27365, 27366, 27368, 27369, 27370, 27371);
  script_xref(name:"RHSA", value:"2006:0602");

  script_name(english:"CentOS 3 / 4 : wireshark (CESA-2006:0602)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Wireshark packages that fix various security vulnerabilities in
Ethereal are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ethereal is a program for monitoring network traffic.

In May 2006, Ethereal changed its name to Wireshark. This update
deprecates the Ethereal packages in Red Hat Enterprise Linux 2.1, 3,
and 4 in favor of the supported Wireshark packages.

Several denial of service bugs were found in Ethereal's protocol
dissectors. It was possible for Ethereal to crash or stop responding
if it read a malformed packet off the network. (CVE-2006-3627,
CVE-2006-3629, CVE-2006-3631)

Several buffer overflow bugs were found in Ethereal's ANSI MAP, NCP
NMAS, and NDPStelnet dissectors. It was possible for Ethereal to crash
or execute arbitrary code if it read a malformed packet off the
network. (CVE-2006-3630, CVE-2006-3632)

Several format string bugs were found in Ethereal's Checkpoint FW-1,
MQ, XML, and NTP dissectors. It was possible for Ethereal to crash or
execute arbitrary code if it read a malformed packet off the network.
(CVE-2006-3628)

Users of Ethereal should upgrade to these updated packages containing
Wireshark version 0.99.2, which is not vulnerable to these issues"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e626ac6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013138.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7d0dc5b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013155.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1df7a994"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013156.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca304b4a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/17");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wireshark-0.99.2-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wireshark-0.99.2-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"wireshark-gnome-0.99.2-EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"wireshark-gnome-0.99.2-EL3.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-0.99.2-EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-0.99.2-EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"wireshark-gnome-0.99.2-EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"wireshark-gnome-0.99.2-EL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
