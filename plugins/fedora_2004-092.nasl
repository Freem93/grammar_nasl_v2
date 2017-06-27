#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-092.
#

include("compat.inc");

if (description)
{
  script_id(13683);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/10/21 21:09:30 $");

  script_cve_id("CVE-2003-0989", "CVE-2004-0055", "CVE-2004-0057");
  script_xref(name:"FEDORA", value:"2004-092");

  script_name(english:"Fedora Core 1 : tcpdump-3.7.2-8.fc1.1 (2004-092)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tcpdump, libpcap, and arpwatch packages fix vulnerabilities in
ISAKMP and RADIUS parsing.

Tcpdump is a command-line tool for monitoring network traffic.

George Bakos discovered flaws in the ISAKMP decoding routines of
tcpdump versions prior to 3.8.1. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2003-0989
to this issue.

Jonathan Heusser discovered an additional flaw in the ISAKMP decoding
routines for tcpdump 3.8.1 and earlier. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0057
to this issue.

Jonathan Heusser discovered a flaw in the print_attr_string function
in the RADIUS decoding routines for tcpdump 3.8.1 and earlier. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0055 to this issue.

Remote attackers could potentially exploit these issues by sending
carefully-crafted packets to a victim. If the victim uses tcpdump,
these pakets could result in a denial of service, or possibly execute
arbitrary code as the 'pcap' user.

Users of tcpdump are advised to upgrade to these erratum packages,
which contain backported security patches and are not vulnerable to
these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-March/000084.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a86e0f3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:arpwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", cpu:"i386", reference:"arpwatch-2.1a11-8.fc1.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"libpcap-0.7.2-8.fc1.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"tcpdump-3.7.2-8.fc1.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"tcpdump-debuginfo-3.7.2-8.fc1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "arpwatch / libpcap / tcpdump / tcpdump-debuginfo");
}
