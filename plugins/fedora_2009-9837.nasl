#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-9837.
#

include("compat.inc");

if (description)
{
  script_id(42387);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/11 13:16:07 $");

  script_cve_id("CVE-2009-2559", "CVE-2009-2560", "CVE-2009-2561", "CVE-2009-2562", "CVE-2009-2563", "CVE-2009-3241", "CVE-2009-3242");
  script_bugtraq_id(35748, 36408, 36846);
  script_xref(name:"FEDORA", value:"2009-9837");

  script_name(english:"Fedora 11 : wireshark-1.2.2-1.fc11 (2009-9837)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to Wireshark 1.2.2 fixing multiple security issues:
http://www.wireshark.org/docs/relnotes/wireshark-1.2.2.html
http://www.wireshark.org/security/wnpa-sec-2009-06.html * The OpcUa
dissector could use excessive CPU and memory. (Bug 3986) Versions
affected: 0.99.6 to 1.0.8, 1.2.0 to 1.2.1 * The GSM A RR dissector
could crash. (Bug 3893) Versions affected: 1.2.0 to 1.2.1 * The TLS
dissector could crash on some platforms. (Bug 4008) Versions affected:
1.2.0 to 1.2.1
http://www.wireshark.org/docs/relnotes/wireshark-1.2.1.html
http://www.wireshark.org/security/wnpa-sec-2009-04.html * The AFS
dissector could crash. (Bug 3564) Versions affected: 0.9.2 to 1.2.0

  - The Infiniband dissector could crash on some platforms.
    Versions affected: 1.0.6 to 1.2.0 * The IPMI dissector
    could overrun a buffer. (Bug 3559) Versions affected:
    1.2.0 * The Bluetooth L2CAP dissector could crash. (Bug
    3572) Versions affected: 1.2.0 * The RADIUS dissector
    could crash. (Bug 3578) Versions affected: 1.2.0 * The
    MIOP dissector could crash. (Bug 3652) Versions
    affected: 1.2.0 * The sFlow dissector could use
    excessive CPU and memory. (Bug 3570) Versions affected:
    1.2.0 (Issues from wnpa-sec-2009-04 does not affect
    users of Wireshark 1.2.1 packages from updates-testing.)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.1.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2009-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2009-06.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=512992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=513008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=513033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=523987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=524001"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-November/030503.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f608355"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"wireshark-1.2.2-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
