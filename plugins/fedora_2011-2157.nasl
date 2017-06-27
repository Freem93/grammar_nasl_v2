#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-2157.
#

include("compat.inc");

if (description)
{
  script_id(52560);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2011-1058");
  script_bugtraq_id(46476);
  script_xref(name:"FEDORA", value:"2011-2157");

  script_name(english:"Fedora 13 : moin-1.9.3-4.fc13 (2011-2157)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Feb 24 2011 Ville-Pekka Vainio <vpivaini AT
    cs.helsinki.fi> - 1.9.3-4

    - Fixes CVE-2011-1058 (rhbz#679523)

    - Tue Feb 8 2011 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1.9.3-3

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

    - Fri Jul 23 2010 Ville-Pekka Vainio <vpivaini AT
      cs.helsinki.fi> 1.9.3-2

    - Rebuilt for
      https://fedoraproject.org/wiki/Features/Python_2.7/Mas
      sRebuild

    - Mon Jun 28 2010 Ville-Pekka Vainio <vpivaini AT
      cs.helsinki.fi> 1.9.3-1

    - Fixes multiple XSS vulnerabilities (rhbz#601399)

    -
      http://hg.moinmo.in/moin/1.9/raw-file/1.9.3/docs/CHANG
      ES

    - Drop integrated security patch

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://hg.moinmo.in/moin/1.9/raw-file/1.9.3/docs/CHANGES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=679523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Features/Python_2.7/MassRebuild"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-March/055124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?728d902e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected moin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC13", reference:"moin-1.9.3-4.fc13")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moin");
}
