#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-8983.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55582);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2011-2216");
  script_bugtraq_id(48096);
  script_xref(name:"FEDORA", value:"2011-8983");

  script_name(english:"Fedora 15 : asterisk-1.8.4.4-2.fc15 (2011-8983)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Remove systemd dependencies from EL6 and F15 The Asterisk Development
Team has announced the release of Asterisk versions 1.4.41.2,
1.6.2.18.2, and 1.8.4.4, which are security releases.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk 1.4.41.2, 1.6.2.18.2, and 1.8.4.4 resolves the
following issue :

AST-2011-011: Asterisk may respond differently to SIP requests from an
invalid SIP user than it does to a user configured on the system, even
when the alwaysauthreject option is set in the configuration. This can
leak information about what SIP users are valid on the Asterisk
system.

For more information about the details of this vulnerability, please
read the security advisory AST-2011-011, which was released at the
same time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.4.41.2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.6.2.18.2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.4.4

Security advisory AST-2011-011 is available at :

http://downloads.asterisk.org/pub/security/AST-2011-011.pdf The
Asterisk Development Team has announced the release of Asterisk
versions 1.4.41.1, 1.6.2.18.1, and 1.8.4.3, which are security
releases.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk 1.4.41.1, 1.6.2.18, and 1.8.4.3 resolves
several issues as outlined below :

  - AST-2011-008: If a remote user sends a SIP packet
    containing a null, Asterisk assumes available data
    extends past the null to the end of the packet when the
    buffer is actually truncated when copied. This causes
    SIP header parsing to modify data past the end of the
    buffer altering unrelated memory structures. This
    vulnerability does not affect TCP/TLS connections. --
    Resolved in 1.6.2.18.1 and 1.8.4.3

  - AST-2011-009: A remote user sending a SIP packet
    containing a Contact header with a missing left angle
    bracket (<) causes Asterisk to access a NULL pointer. --
    Resolved in 1.8.4.3

  - AST-2011-010: A memory address was inadvertently
    transmitted over the network via IAX2 via an option
    control frame and the remote party would try to access
    it. -- Resolved in 1.4.41.1, 1.6.2.18.1, and 1.8.4.3

The issues and resolutions are described in the AST-2011-008,
AST-2011-009, and AST-2011-010 security advisories.

For more information about the details of these vulnerabilities,
please read the security advisories AST-2011-008, AST-2011-009, and
AST-2011-010, which were released at the same time as this
announcement.

For a full list of changes in the current releases, please see the
ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.4.41.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.6.2.18.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.4.3

Security advisories AST-2011-008, AST-2011-009, and AST-2011-010 are
available at :

http://downloads.asterisk.org/pub/security/AST-2011-008.pdf
http://downloads.asterisk.org/pub/security/AST-2011-009.pdf
http://downloads.asterisk.org/pub/security/AST-2011-010.pdf

The Asterisk Development Team has announced the release of Asterisk
version 1.8.4.2, which is a security release for Asterisk 1.8.

This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk 1.8.4.2 resolves an issue with SIP URI parsing
which can lead to a remotely exploitable crash :

Remote Crash Vulnerability in SIP channel driver (AST-2011-007)

The issue and resolution is described in the AST-2011-007 security
advisory.

For more information about the details of this vulnerability, please
read the security advisory AST-2011-007, which was released at the
same time as this announcement.

For a full list of changes in the current release, please see the
ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.4.2

Security advisory AST-2011-007 is available at :

http://downloads.asterisk.org/pub/security/AST-2011-007.pdf

The Asterisk Development Team has announced the release of Asterisk
1.8.4.1. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/

The release of Asterisk 1.8.4.1 resolves several issues reported by
the community. Without your help this release would not have been
possible. Thank you!

Below is a list of issues resolved in this release :

  - Fix our compliance with RFC 3261 section 18.2.2. (aka
    Cisco phone fix) (Closes issue #18951. Reported by jmls.
    Patched by wdoekes)

  - Resolve a change in IPv6 header parsing due to the Cisco
    phone fix issue. This issue was found and reported by
    the Asterisk test suite. (Closes issue #18951. Patched
    by mnicholson)

  - Resolve potential crash when using SIP TLS support.
    (Closes issue #19192. Reported by stknob. Patched by
    Chainsaw. Tested by vois, Chainsaw)

  - Improve reliability when using SIP TLS. (Closes issue
    #19182. Reported by st. Patched by mnicholson)

For a full list of changes in this release candidate, please see the
ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.8.4.1

The Asterisk Development Team has announced the release of Asterisk
1.8.4. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/

The release of Asterisk 1.8.4 resolves several issues reported by the
community. Without your help this release would not have been
possible. Thank you!

Below is a sample of the issues resolved in this release :

  - Use SSLv23_client_method instead of old SSLv2 only.
    (Closes issue #19095, #19138. Reported, patched by
    tzafrir. Tested by russell and chazzam.

  - Resolve crash in ast_mutex_init() (Patched by twilson)

  - Resolution of several DTMF based attended transfer
    issues. (Closes issue #17999, #17096, #18395, #17273.
    Reported by iskatel, gelo, shihchuan, grecco. Patched by
    rmudgett)

    NOTE: Be sure to read the ChangeLog for more information
    about these changes.

  - Resolve deadlocks related to device states in chan_sip
    (Closes issue #18310. Reported, patched by one47.
    Patched by jpeeler)

  - Resolve an issue with the Asterisk manager interface
    leaking memory when disabled. (Reported internally by
    kmorgan. Patched by russellb)

  - Support greetingsfolder as documented in
    voicemail.conf.sample. (Closes issue #17870. Reported by
    edhorton. Patched by seanbright)

  - Fix channel redirect out of MeetMe() and other issues
    with channel softhangup (Closes issue #18585. Reported
    by oej. Tested by oej, wedhorn, russellb. Patched by
    russellb)

  - Fix voicemail sequencing for file based storage. (Closes
    issue #18498, #18486. Reported by JJCinAZ, bluefox.
    Patched by jpeeler)

  - Set hangup cause in local_hangup so the proper return
    code of 486 instead of 503 when using Local channels
    when the far sides returns a busy. Also affects CCSS in
    Asterisk 1.8+. (Patched by twilson)

  - Fix issues with verbose messages not being output to the
    console. (Closes issue #18580. Reported by pabelanger.
    Patched by qwell)

  - Fix Deadlock with attended transfer of SIP call (Closes
    issue #18837. Reported, patched by alecdavis. Tested by
    alecdavid, Irontec, ZX81, cmaj)

Includes changes per AST-2011-005 and AST-2011-006 For a full list of
changes in this release candidate, please see the ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.8.4

Information about the security releases are available at :

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
    value:"http://downloads.asterisk.org/pub/security/AST-2011-007.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-008.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-009.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-010.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2011-011.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.8.4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.8.4.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.4.41.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f623297e"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.4.41.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?522eebb4"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.6.2.18.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b0db8bb"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.6.2.18.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9ade373"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.4.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fbe6608"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.4.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ab370c4"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.4.4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?def551e4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=710441"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062658.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?321c2c0c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/13");
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
if (rpm_check(release:"FC15", reference:"asterisk-1.8.4.4-2.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "asterisk");
}
