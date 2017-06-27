#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-8432.
#

include("compat.inc");

if (description)
{
  script_id(40534);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:50:39 $");

  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_xref(name:"FEDORA", value:"2009-8432");

  script_name(english:"Fedora 10 : subversion-1.6.4-2.fc10 (2009-8432)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of Subversion,
including several enhancements, many bug fixes, and a fix for a
security issue: Matt Lewis reported multiple heap overflow flaws in
Subversion (servers and clients) when parsing binary deltas. Malicious
users with commit access to a vulnerable server could uses these flaws
to cause a heap overflow on the server running Subversion. A malicious
Subversion server could use these flaws to cause a heap overflow on
vulnerable clients when they attempt to checkout or update, resulting
in a crash or, possibly, arbitrary code execution on the vulnerable
client. (CVE-2009-2411) Version 1.6 offers many bug fixes and
enhancements over 1.5, with the notable major features: - identical
files share storage space in repository - file-externals support for
intra-repository files - 'tree' conflicts now handled more gracefully
- repository root relative URL support on most commands For more
information on changes in 1.6, see the release notes:
http://subversion.tigris.org/svn_1.6_releasenotes.html This update
includes the latest release of Subversion, version 1.6.2. Version 1.6
offers many bug fixes and enhancements over 1.5, with the notable
major features: * identical files share storage space in repository *
file- externals support for intra-repository files * 'tree' conflicts
now handled more gracefully * repository root relative URL support on
most commands

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://subversion.tigris.org/svn_1.6_releasenotes.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=514744"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027739.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60939a02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"subversion-1.6.4-2.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
