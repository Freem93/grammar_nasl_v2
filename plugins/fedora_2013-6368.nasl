#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-6368.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66224);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/20 13:54:17 $");

  script_bugtraq_id(58504, 58507, 59131, 59141, 59153, 59159, 59162, 59165, 59166, 59167, 59170, 59179, 59184, 59187, 59190, 59194, 59206, 59212, 59213, 59219, 59228, 59243);
  script_xref(name:"FEDORA", value:"2013-6368");

  script_name(english:"Fedora 19 : java-1.7.0-openjdk-1.7.0.19-2.3.9.6.fc19 (2013-6368)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update is fixing -
https://admin.fedoraproject.org/updates/FEDORA-2013-5861/java-1.7.0-op
enjdk-1.7.0.19-2.3.9.1.fc19

So except the expected inherited fixes listed below, it contains new
accessibility package: package accessibility Summary: OpenJDK
accessibility connector Requires: java-atk-wrapper Requires:
java-1.7.0-openjdk-1.7.0.19-2.3.9.6.fc19

description Enables accessibility support in OpenJDK by using
java-at-wrapper. This allows compatible at-spi2 based accessibility
programs to work for AWT and Swing-based programs. Please note, the
java-atk-wrapper is still in beta, and also OpenJDK itself is still in
phase of tuning to be working with accessibility features. Although
working pretty fine, there are known issues with accessibility on, so
do not rather install this package unless you really need.

Also the alternative archs tarball is updated.

Inherited fixes :

  - updated to updated IcedTea 2.3.9 with fix to one of
    security fixes

    - fixed font glyph offset arm...)builds!

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
      it correctly Fix FTBFS on Secondary Arches

  - updated to updated IcedTea 2.3.9 with fix to one of
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
  # https://admin.fedoraproject.org/updates/FEDORA-2013-5861/java-1.7.0-openjdk-1.7.0.19-2.3.9.1.fc19
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7d3db4f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-April/103629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7883b17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Reflection Type Confusion Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"java-1.7.0-openjdk-1.7.0.19-2.3.9.6.fc19")) flag++;


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
