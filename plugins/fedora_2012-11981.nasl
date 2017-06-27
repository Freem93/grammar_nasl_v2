#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-11981.
#

include("compat.inc");

if (description)
{
  script_id(62131);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 22:25:11 $");

  script_cve_id("CVE-2012-4286", "CVE-2012-4287", "CVE-2012-4294", "CVE-2012-4295", "CVE-2012-4298");
  script_xref(name:"FEDORA", value:"2012-11981");

  script_name(english:"Fedora 18 : wireshark-1.8.2-1.fc18 (2012-11981)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upgrade to wireshark 1.8.2

The following vulnerabilities have been fixed.

wnpa-sec-2012-13:The DCP ETSI dissector could trigger a zero division.
wnpa-sec-2012-14: The MongoDB dissector could go into a large loop.
wnpa-sec-2012-15: The XTP dissector could go into an infinite loop.
wnpa-sec-2012-16: The ERF dissector could overflow a buffer.
wnpa-sec-2012-17: AFP dissector could go into a large loop.
wnpa-sec-2012-18: RTPS2 dissector could overflow a buffer.
wnpa-sec-2012-19: GSM RLC MAC dissector could overflow a buffer.
wnpa-sec-2012-20: CIP dissector could exhaust system memory.
wnpa-sec-2012-21: STUN dissector could crash. wnpa-sec-2012-22:
EtherCAT Mailbox dissector could abort. wnpa-sec-2012-23: CTDB
dissector could go into a large loop. wnpa-sec-2012-24: pcap-ng file
parser could trigger a zero division. wnpa-sec-2012-25: Ixia
IxVeriWave file parser could overflow a buffer.

See http://www.wireshark.org/docs/relnotes/wireshark-1.8.2.html for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=848544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=848554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=848584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=848588"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/086860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fa43777"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"wireshark-1.8.2-1.fc18")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
