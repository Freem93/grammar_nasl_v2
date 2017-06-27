#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-6012.
#

include("compat.inc");

if (description)
{
  script_id(47409);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/20 21:38:17 $");

  script_cve_id("CVE-2010-0828");
  script_bugtraq_id(39110);
  script_osvdb_id(63362);
  script_xref(name:"FEDORA", value:"2010-6012");
  script_xref(name:"Secunia", value:"38444");

  script_name(english:"Fedora 11 : moin-1.8.7-2.fc11 (2010-6012)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Sat Apr 3 2010 Ville-Pekka Vainio <vpivaini AT
    cs.helsinki.fi> - 1.8.7-2

    - Fixes CVE-2010-0828 (rhbz#578801)

    - Thu Feb 18 2010 Ville-Pekka Vainio <vpivaini AT
      cs.helsinki.fi> - 1.8.7-1

    - Fixed major security issues in miscellaneous parts of
      moin

    -
      http://hg.moinmo.in/moin/1.8/raw-file/1.8.7/docs/CHANG
      ES

    - http://secunia.com/advisories/38444/

    - Fixes rhbz#565604

    - Mon Dec 28 2009 Ville-Pekka Vainio <vpivaini AT
      cs.helsinki.fi> - 1.8.6-1

    - 1.8.6, mostly bug fixes

    -
      http://hg.moinmo.in/moin/1.8/raw-file/1.8.6/docs/CHANG
      ES

    - Tue Sep 15 2009 Ville-Pekka Vainio <vpivaini AT
      cs.helsinki.fi> - 1.8.5-1

    - 1.8.5

    - Includes multiple bug fixes, a new FCKeditor version
      and some new features

    -
      http://hg.moinmo.in/moin/1.8/raw-file/1.8.5/docs/CHANG
      ES

    - Sat Jul 25 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 1.8.4-3

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

    - Sun Jul 12 2009 Ville-Pekka Vainio <vpivaini AT
      cs.helsinki.fi> 1.8.4-2

    - Remove the filemanager directory from the embedded
      FCKeditor, it contains code with know security
      vulnerabilities, even though that code couldn't be
      invoked when moin was used with the default settings.

  - Fixes rhbz #509924, related to CVE-2009-2265

    - Sat Jun 13 2009 Ville-Pekka Vainio <vpivaini AT
      cs.helsinki.fi> 1.8.4-1

    - Update to 1.8.4, http://moinmo.in/MoinMoinRelease1.8
      has a list of changes.

  - Includes a security fix for hierarchical ACL (not the
    default mode), http://moinmo.in/SecurityFixes has the
    details.

  - Drop previous security patches, those are not needed
    anymore.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://hg.moinmo.in/moin/1.8/raw-file/1.8.5/docs/CHANGES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://hg.moinmo.in/moin/1.8/raw-file/1.8.6/docs/CHANGES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://hg.moinmo.in/moin/1.8/raw-file/1.8.7/docs/CHANGES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moinmo.in/MoinMoinRelease1.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://moinmo.in/SecurityFixes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=578801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038490.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1ebc367"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected moin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC11", reference:"moin-1.8.7-2.fc11")) flag++;


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
