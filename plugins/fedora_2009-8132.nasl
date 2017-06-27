#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-8132.
#

include("compat.inc");

if (description)
{
  script_id(40452);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:21:56 $");

  script_cve_id("CVE-2009-1720", "CVE-2009-1721");
  script_bugtraq_id(35838);
  script_xref(name:"FEDORA", value:"2009-8132");

  script_name(english:"Fedora 11 : OpenEXR-1.6.1-8.fc11 (2009-8132)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jul 29 2009 Rex Dieter <rdieter at
    fedoraproject.org> 1.6.1-8

    - CVE-2009-1720 OpenEXR: Multiple integer overflows
      (#513995)

    - CVE-2009-1721 OpenEXR: Invalid pointer free by image
      decompression (#514003)

    - Fri Jul 24 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1.6.1-7

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=513995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=514003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-July/027215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?618a01b9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenEXR package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:OpenEXR");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/01");
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
if (rpm_check(release:"FC11", reference:"OpenEXR-1.6.1-8.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenEXR");
}
