#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6517.
#

include("compat.inc");

if (description)
{
  script_id(33541);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 22:23:16 $");

  script_cve_id("CVE-2008-2785");
  script_bugtraq_id(29802);
  script_xref(name:"FEDORA", value:"2008-6517");

  script_name(english:"Fedora 8 : seamonkey-1.1.11-1.fc8 (2008-6517)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated seamonkey packages that fix several security issues are now
available for Fedora 8. An integer overflow flaw was found in the way
SeaMonkey displayed certain web content. A malicious website could
cause SeaMonkey to crash, or execute arbitrary code with the
permissions of the user running SeaMonkey. (CVE-2008-2785) Updated
packages update SeaMonkey to upstream version 1.1.11 to address this
flaw: http://www.mozilla.org/security/known-
vulnerabilities/seamonkey11.html#seamonkey1.1.11

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452204"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012547.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?739c73e6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"seamonkey-1.1.11-1.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}
