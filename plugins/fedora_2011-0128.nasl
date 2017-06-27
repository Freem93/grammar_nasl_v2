#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-0128.
#

include("compat.inc");

if (description)
{
  script_id(51515);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2010-4538");
  script_osvdb_id(70244);
  script_xref(name:"FEDORA", value:"2011-0128");

  script_name(english:"Fedora 14 : wireshark-1.4.2-2.fc14 (2011-0128)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jan 5 2011 Jan Safranek <jsafrane at redhat.com> -
    1.4.2-2

    - fixed buffer overflow in ENTTEC dissector (#666897)

    - Mon Nov 22 2010 Jan Safranek <jsafrane at redhat.com>
      - 1.4.2-1

    - upgrade to 1.4.2

    - see
      http://www.wireshark.org/docs/relnotes/wireshark-1.4.2
      .html

    - Mon Nov 1 2010 Jan Safranek <jsafrane at redhat.com> -
      1.4.1-2

    - temporarily disable zlib until
      https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=49
      55 is resolved (#643461)

  - Fri Oct 22 2010 Jan Safranek <jsafrane at redhat.com> -
    1.4.1-1

    - upgrade to 1.4.1

    - see
      http://www.wireshark.org/docs/relnotes/wireshark-1.4.1
      .html

    - Own the %{_libdir}/wireshark dir (#644508)

    - associate *.pcap files with wireshark (#641163)

    - Tue Oct 5 2010 jkeating - 1.4.0-2.1

    - Rebuilt for gcc bug 634757

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.1.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=666894"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/053042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aafe3214"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/14");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"wireshark-1.4.2-2.fc14")) flag++;


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
