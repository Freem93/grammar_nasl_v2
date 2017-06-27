#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-8914.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(55581);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/20 22:15:24 $");

  script_cve_id("CVE-2011-2529", "CVE-2011-2535", "CVE-2011-2665");
  script_bugtraq_id(48431);
  script_osvdb_id(73307, 73308, 73309);
  script_xref(name:"FEDORA", value:"2011-8914");

  script_name(english:"Fedora 14 : asterisk-1.6.2.19-1.fc14 (2011-8914)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced the final maintenance
release of Asterisk, version 1.6.2.19. This release is available for
immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/

Please note that Asterisk 1.6.2.19 is the final maintenance release
from the 1.6.2 branch. Support for security related issues will
continue until April 21, 2012. For more information about support of
the various Asterisk branches, see
https://wiki.asterisk.org/wiki/display/AST/Asterisk+Versions

The release of Asterisk 1.6.2.19 resolves several issues reported by
the community and would have not been possible without your
participation. Thank you!

The following is a sample of the issues resolved in this release :

  - Don't broadcast FullyBooted to every AMI connection The
    FullyBooted event should not be sent to every AMI
    connection every time someone connects via AMI. It
    should only be sent to the user who just connected.
    (Closes issue #18168. Reported, patched by FeyFre)

  - Fix thread blocking issue in the sip TCP/TLS
    implementation. (Closes issue #18497. Reported by vois.
    Tested by vois, rossbeer, kowalma, Freddi_Fonet. Patched
    by dvossel)

  - Don't delay DTMF in core bridge while listening for DTMF
    features. (Closes issue #15642, #16625. Reported by
    jasonshugart, sharvanek. Tested by globalnetinc, jde.
    Patched by oej, twilson)

  - Fix chan_local crashs in local_fixup() Thanks OEJ for
    tracking down the issue and submitting the patch.
    (Closes issue #19053. Reported, patched by oej)

  - Don't offer video to directmedia callee unless caller
    offered it as well (Closes issue #19195. Reported,
    patched by one47)

Additionally security announcements AST-2011-008, AST-2011-010, and
AST-2011-011 have been resolved in this release.

For a full list of changes in this release, please see the ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.6.2.1
9 The Asterisk Development Team has announced the release of Asterisk
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

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
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
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.6.2.19
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34b848ec"
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
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.6.2.18.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b0db8bb"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.4.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ab370c4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6789a211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.asterisk.org/wiki/display/AST/Asterisk+Versions"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC14", reference:"asterisk-1.6.2.19-1.fc14")) flag++;


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
