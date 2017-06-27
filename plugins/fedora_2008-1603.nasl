#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-1603.
#

include("compat.inc");

if (description)
{
  script_id(31074);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2007-5333", "CVE-2007-5342", "CVE-2007-6286", "CVE-2008-0002");
  script_bugtraq_id(27006, 27703, 27706);
  script_xref(name:"FEDORA", value:"2008-1603");

  script_name(english:"Fedora 8 : tomcat5-5.5.26-1jpp.2.fc8 (2008-1603)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Feb 12 2008 Devrim GUNDUZ <devrim at
    commandprompt.com> 0:5.5.26-1jpp.2

    - Rebuilt

    - Fri Feb 8 2008 Devrim GUNDUZ <devrim at
      commandprompt.com> 0:5.5.26-1jpp.1

    - Update to new upstream version, which also fixes the
      following :

    - CVE-2007-5342

    - CVE-2007-5333

    - CVE-2007-5461

    - CVE-2007-6286

    - Removed patch20, now in upstream.

    - Sat Jan 5 2008 Devrim GUNDUZ <devrim at
      commandprompt.com> 0:5.5.25-2jpp.2

    - Fix for bz #153187

    - Fix init script for bz #380921

    - Fix tomcat5.conf and spec file for bz #253605

    - Fix for bz #426850

    - Fix for bz #312561

    - Fix init script, per bz #247077

    - Fix builds on alpha, per bz #253827

    - Thu Nov 15 2007 Devrim GUNDUZ <devrim at
      commandprompt.com> 0:5.5.25-1jpp.1

    - Updated to 5.5.25, to fix the following issues :

    - CVE-2007-1355

    - CVE-2007-3386

    - CVE-2007-3385

    - CVE-2007-3382

    - CVE-2007-2450, RH bugzilla #244808, #244810, #244812,
      #363081

    - CVE-2007-2449, RH bugzilla #244810, #244812, #244804,
      #363081

    - Applied patch(20) for RH bugzilla #333791,
      CVE-2007-5461

    - Applied patch(21) for RH bugzilla #244803, #244812,
      #363081, CVE-2007-1358

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=427216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=427766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=432327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=432332"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?496d579c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat5 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tomcat5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC8", reference:"tomcat5-5.5.26-1jpp.2.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat5");
}
