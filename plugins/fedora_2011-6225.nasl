#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-6225.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(54286);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:32:16 $");

  script_cve_id("CVE-2011-1507", "CVE-2011-1599");
  script_bugtraq_id(47537);
  script_xref(name:"FEDORA", value:"2011-6225");

  script_name(english:"Fedora 14 : asterisk-1.6.2.18-1.fc14 (2011-6225)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced the release of Asterisk
1.6.2.18. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/

The release of Asterisk 1.6.2.18 resolves several issues reported by
the community and would have not been possible without your
participation. Thank you!

The following is a sample of the issues resolved in this release :

  - Only offer codecs both sides support for directmedia.
    (Closes issue #17403. Reported, patched by one47)

  - Resolution of several DTMF based attended transfer
    issues. (Closes issue #17999, #17096, #18395, #17273.
    Reported by iskatel, gelo, shihchuan, grecco. Patched by
    rmudgett) NOTE: Be sure to read the ChangeLog for more
    information about these changes.

  - Resolve deadlocks related to device states in chan_sip
    (Closes issue #18310. Reported, patched by one47.
    Patched by jpeeler)

  - Fix channel redirect out of MeetMe() and other issues
    with channel softhangup (Closes issue #18585. Reported
    by oej. Tested by oej, wedhorn, russellb. Patched by
    russellb)

  - Fix voicemail sequencing for file based storage. (Closes
    issue #18498, #18486. Reported by JJCinAZ, bluefox.
    Patched by jpeeler)

  - Guard against retransmitting BYEs indefinitely during
    attended transfers with chan_sip. (Review:
    https://reviewboard.asterisk.org/r/1077/)

In addition to the changes listed above, commits to resolve security
issues AST-2011-005 and AST-2011-006 have been merged into this
release. More information about AST-2011-005 and AST-2011-006 can be
found at :

http://downloads.asterisk.org/pub/security/AST-2011-005.pdf
http://downloads.asterisk.org/pub/security/AST-2011-006.pdf

For a full list of changes in this release, please see the ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.6.2.1
8

The Asterisk Development Team has announced security releases for
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
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.6.2.18
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b2e393f"
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-May/060200.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3b7ac52"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://reviewboard.asterisk.org/r/1077/"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/17");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"asterisk-1.6.2.18-1.fc14")) flag++;


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
