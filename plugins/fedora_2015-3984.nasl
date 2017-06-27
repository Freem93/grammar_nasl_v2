#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-3984.
#

include("compat.inc");

if (description)
{
  script_id(82280);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 23:06:18 $");

  script_bugtraq_id(71689, 71690, 71691, 71693, 71695, 71696, 71697, 71698);
  script_xref(name:"FEDORA", value:"2015-3984");

  script_name(english:"Fedora 21 : ettercap-0.8.2-1.fc21 (2015-3984)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"0.8.2-Ferri

Bug Fix !! Fixed some openssl deprecated functions usage !! Fixed log
file ownership !! Fixed mixed output print !! Fixed drop_privs
function usage !! Fixed nopromisc option usage. !! Fixed missing break
in parser code. !! Improved redirect commands !! Fix truncated VLAN
packet headers !! Fix ettercap.rc file (windows only) !! Various cmake
fixes !! A ton of BSD bug fixes !! Simplify macosx cmake files !! Fix
incorrect sequence number after TCP injection !! Fix pcap length, and
aligment problems with libpcap !! Bug fixes and gtk code refactor (gtk
box wrapper) !! Fix some ipv6 send issues !! Fixed sleep time on
Windows (high CPU usage) !! Fixed many CVE vulnerabilities (some of
them already fixed in 0.8.1)

  - CVE-2014-6395 (Length Parameter Inconsistency)

    - CVE-2014-6396 (Arbitrary write)

    - CVE-2014-9376 (Negative index/underflow)

    - CVE-2014-9377 (Heap overflow)

    - CVE-2014-9378 (Unchecked return value)

    - CVE-2014-9379 (Incorrect cast)

    - CVE-2014-9380 (Buffer over-read)

    - CVE-2014-9381 (Signedness error)

      New Features + Updated etter.finger.mac + Add TXT and
      ANY query support on dns_spoof + New macosx travis-ci
      build! + Enable again PDF generation

      Removed

  - Remove gprof support

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/153096.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41cc9378"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ettercap package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ettercap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"ettercap-0.8.2-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ettercap");
}
