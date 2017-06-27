#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-2620.
#

include("compat.inc");

if (description)
{
  script_id(52640);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/20 22:05:53 $");

  script_cve_id("CVE-2010-3445", "CVE-2011-0538", "CVE-2011-0713", "CVE-2011-1138", "CVE-2011-1139", "CVE-2011-1140", "CVE-2011-1141", "CVE-2011-1143");
  script_osvdb_id(71549, 71552, 71553, 71554, 71555, 71556);
  script_xref(name:"FEDORA", value:"2011-2620");

  script_name(english:"Fedora 13 : wireshark-1.2.15-1.fc13 (2011-2620)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security bugs were fixed in this release :

  - CVE-2011-0538: memory corruption when reading a
    malformed pcap file

    - CVE-2010-3445: stack overflow in BER dissector

    - CVE-2011-1143: NULL pointer dereference causing
      application crash when reading malformed pcap file

    - CVE-2011-1140: Multiple stack consumption
      vulnerabilities caused DoS via crafted SMB or CLDAP
      packet

    - CVE-2011-1141: Malformed LDAP filter string causes
      Denial of Service via excessive memory consumption

    - CVE-2011-1138: Off-by-one error in the
      dissect_6lowpan_iphc function causes application crash
      (Denial Of Service)

    - CVE-2011-1139: Denial Of Service (application crash)
      via a pcap-ng file that contains a large packet-length
      field

    - CVE-2011-0713: heap-based buffer overflow when reading
      malformed Nokia DCT3 phone signaling traces

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=676232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=678198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=681748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=681753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=681754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=681756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=681760"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/055664.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bf89204"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"wireshark-1.2.15-1.fc13")) flag++;


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
