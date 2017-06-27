#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6518.
#

include("compat.inc");

if (description)
{
  script_id(33542);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:21:53 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933");
  script_bugtraq_id(29802, 30242);
  script_xref(name:"FEDORA", value:"2008-6518");

  script_name(english:"Fedora 9 : devhelp-0.19.1-3.fc9 / epiphany-2.22.2-3.fc9 / epiphany-extensions-2.22.1-3.fc9 / etc (2008-6518)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Fedora 9. An integer overflow flaw was found in the way
Firefox displayed certain web content. A malicious website could cause
Firefox to crash, or execute arbitrary code with the permissions of
the user running Firefox. (CVE-2008-2785) A flaw was found in the way
Firefox handled certain command line URLs. If another application
passed Firefox a malformed URL, it could result in Firefox executing
local malicious content with chrome privileges. (CVE-2008-2933)
Updated packages update Mozilla Firefox to upstream version 3.0.1 to
address these flaws: http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.1 This update also contains
devhelp, epiphany, epiphany-extensions, and yelp packages rebuilt
against new Firefox / Gecko libraries.

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
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=454697"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d274af40"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeedb76f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c69f870"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012539.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a7c4350"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?adf48c9d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41c6c0c6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/18");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"devhelp-0.19.1-3.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-2.22.2-3.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-extensions-2.22.1-3.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"firefox-3.0.1-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"xulrunner-1.9.0.1-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"yelp-2.22.1-4.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / epiphany / epiphany-extensions / firefox / xulrunner / etc");
}
