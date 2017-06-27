#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-5835.
#

include("compat.inc");

if (description)
{
  script_id(53566);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2011-1507", "CVE-2011-1599");
  script_bugtraq_id(47537);
  script_xref(name:"FEDORA", value:"2011-5835");

  script_name(english:"Fedora 15 : asterisk-1.8.3.3-1.fc15 (2011-5835)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced security releases for
Asterisk branches 1.4, 1.6.1, 1.6.2, and 1.8. The available security
releases are released as versions 1.4.40.1, 1.6.1.25, 1.6.2.17.3, and
1.8.3.3.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The releases of Asterisk 1.4.40.1, 1.6.1.25, 1.6.2.17.3, and 1.8.3.3
resolve two issues :

  - File Descriptor Resource Exhaustion (AST-2011-005)

    - Asterisk Manager User Shell Access (AST-2011-006)

The issues and resolutions are described in the AST-2011-005 and
AST-2011-006 security advisories.

For more information about the details of these vulnerabilities,
please read the security advisories AST-2011-005 and AST-2011-006,
which were released at the same time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.4.40.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.6.1.25
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.6.2.17.3
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.3.3

Security advisory AST-2011-005 and AST-2011-006 are available at :

http://downloads.asterisk.org/pub/security/AST-2011-005.pdf
http://downloads.asterisk.org/pub/security/AST-2011-006.pdf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-005.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-006.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.4.40.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb56878c"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.6.1.25
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3157653f"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.6.2.17.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7b1180e"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.3.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58e47bf4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=698916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=698917"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-April/058922.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2aa6caf8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/27");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"asterisk-1.8.3.3-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asterisk");
}
