#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-5958.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66010);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 21:56:44 $");

  script_xref(name:"FEDORA", value:"2013-5958");

  script_name(english:"Fedora 18 : java-1.7.0-openjdk-1.7.0.19-2.3.9.1.fc18 (2013-5958)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - updated to updated IcedTea 2.3.9 with fix to one of
    security fixes

    - fixed font glyph offset WARNING - this build have not
      yet updated not-hotspot (arm...)builds!

  - added client to ghosted classes.jsa

    - updated to IcedTea 2.3.9 with latest security patches

    - 920245 CVE-2013-0401 OpenJDK: unspecified sandbox
      bypass (CanSecWest 2013, AWT)

    - 920247 CVE-2013-1488 OpenJDK: unspecified sanbox
      bypass (CanSecWest 2013, Libraries)

    - 952387 CVE-2013-1537 OpenJDK: remote code loading
      enabled by default (RMI, 8001040)

    - 952389 CVE-2013-2415 OpenJDK: temporary files created
      with insecure permissions (JAX-WS, 8003542)

    - 952398 CVE-2013-2423 OpenJDK: incorrect setter access
      checks in MethodHandles (Hostspot, 8009677)

    - 952509 CVE-2013-2424 OpenJDK: MBeanInstantiator
      insufficient class access checks (JMX, 8006435)

    - 952521 CVE-2013-2429 OpenJDK: JPEGImageWriter state
      corruption (ImageIO, 8007918)

    - 952524 CVE-2013-2430 OpenJDK: JPEGImageReader state
      corruption (ImageIO, 8007667)

    - 952550 CVE-2013-2436 OpenJDK: Wrapper.convert
      insufficient type checks (Libraries, 8009049)

    - 952638 CVE-2013-2420 OpenJDK: image processing
      vulnerability (2D, 8007617)

    - 952640 CVE-2013-1558 OpenJDK:
      java.beans.ThreadGroupContext missing restrictions
      (Beans, 7200507)

    - 952642 CVE-2013-2422 OpenJDK: MethodUtil trampoline
      class incorrect restrictions (Libraries, 8009857)

    - 952645 CVE-2013-2431 OpenJDK: Hotspot intrinsic frames
      vulnerability (Hotspot, 8004336)

    - 952646 CVE-2013-1518 OpenJDK: JAXP missing security
      restrictions (JAXP, 6657673)

    - 952648 CVE-2013-1557 OpenJDK:
      LogStream.setDefaultStream() missing security
      restrictions (RMI, 8001329)

    - 952649 CVE-2013-2421 OpenJDK: Hotspot MethodHandle
      lookup error (Hotspot, 8009699)

    - 952653 CVE-2013-2426 OpenJDK: ConcurrentHashMap
      incorrectly calls defaultReadObject() method
      (Libraries, 8009063)

    - 952656 CVE-2013-2419 OpenJDK: font processing errors
      (2D, 8001031)

    - 952657 CVE-2013-2417 OpenJDK: Network InetAddress
      serialization information disclosure (Networking,
      8000724)

    - 952708 CVE-2013-2383 OpenJDK: font layout and glyph
      table errors (2D, 8004986)

    - 952709 CVE-2013-2384 OpenJDK: font layout and glyph
      table errors (2D, 8004987)

    - 952711 CVE-2013-1569 OpenJDK: font layout and glyph
      table errors (2D, 8004994)

    - buildver sync to b19

    - rewritten
      java-1.7.0-openjdk-java-access-bridge-security.patch

    - fixed priority (one zero deleted)

    - unapplied patch2

    - added patch107 abrt_friendly_hs_log_jdk7.patch

    - removed patch2
      java-1.7.0-openjdk-java-access-bridge-idlj.patch

    - removed redundant rm of classes.jsa, ghost is handling
      it correctly

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-April/102077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fe89c8e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC18", reference:"java-1.7.0-openjdk-1.7.0.19-2.3.9.1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk");
}
