#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-16941.
#

include("compat.inc");

if (description)
{
  script_id(50444);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/28 18:33:26 $");

  script_osvdb_id(68079, 68844, 68845, 68846, 68847, 68849, 68850, 68851, 68853, 68854, 68921);
  script_xref(name:"FEDORA", value:"2010-16941");

  script_name(english:"Fedora 12 : sunbird-1.0-0.26.20090916hg.fc12 / thunderbird-3.0.10-1.fc12 (2010-16941)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Thunderbird version 3.0.10, fixing multiple
security issues detailed in the upstream advisory :

  -
    http://www.mozilla.org/security/known-vulnerabilities/th
    underbird30.html#thunderbird3.0.9

    -
      http://www.mozilla.org/security/known-vulnerabilities/
      thunderbird30.html#thunderbird3.0.10

Update also includes sunbird package rebuilt against new version of
Thunderbird.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird30.html#thunderbird3.0.10
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bad7b2cb"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird30.html#thunderbird3.0.9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a67d4bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/050216.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b4fba3e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-November/050217.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c402853f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sunbird and / or thunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sunbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"sunbird-1.0-0.26.20090916hg.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"thunderbird-3.0.10-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sunbird / thunderbird");
}
