#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0658 and 
# CentOS Errata and Security Advisory 2006:0658 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22337);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-4330", "CVE-2006-4331", "CVE-2006-4333");
  script_osvdb_id(28196, 28197, 28199);
  script_xref(name:"RHSA", value:"2006:0658");

  script_name(english:"CentOS 3 / 4 : wireshark (CESA-2006:0658)");
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

Bugs were found in Wireshark's SCSI and SSCOP protocol dissectors.
Ethereal could crash or stop responding if it read a malformed packet
off the network. (CVE-2006-4330, CVE-2006-4333)

An off-by-one bug was found in the IPsec ESP decryption preference
parser. Ethereal could crash or stop responding if it read a malformed
packet off the network. (CVE-2006-4331)

Users of Wireshark or Ethereal should upgrade to these updated
packages containing Wireshark version 0.99.3, which is not vulnerable
to these issues. These packages also fix a bug in the PAM
configuration of the Wireshark packages which prevented non-root users
starting a capture."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013220.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c546f9f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27f0962c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013236.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e2c33ec"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a17bb0a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013246.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3caa7d3c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06351852"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/23");
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
if (rpm_check(release:"CentOS-3", reference:"wireshark-0.99.3-EL3.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"wireshark-gnome-0.99.3-EL3.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"wireshark-0.99.3-EL4.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"wireshark-gnome-0.99.3-EL4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
