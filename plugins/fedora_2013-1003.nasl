#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-1003.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64372);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/19 21:02:56 $");

  script_cve_id("CVE-2012-5976", "CVE-2012-5977");
  script_xref(name:"FEDORA", value:"2013-1003");

  script_name(english:"Fedora 18 : asterisk-11.2.0-1.fc18 (2013-1003)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced the release of Asterisk
11.2.0. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk

The release of Asterisk 11.2.0 resolves several issues reported by the
community and would have not been possible without your participation.
Thank you!

The following is a sample of the issues resolved in this release :

  - --- app_meetme: Fix channels lingering when hung up
    under certain conditions (Closes issue ASTERISK-20486.
    Reported by Michael Cargile)

  - --- Fix stuck DTMF when bridge is broken. (Closes issue
    ASTERISK-20492. Reported by Jeremiah Gowdy)

  - --- Add missing support for 'who hung up' to chan_motif.
    (Closes issue ASTERISK-20671. Reported by Matt Jordan)

  - --- Remove a fixed size limitation for producing SDP and
    change how ICE support is disabled by default. (Closes
    issue ASTERISK-20643. Reported by coopvr)

  - --- Fix chan_sip websocket payload handling (Closes
    issue ASTERISK-20745. Reported by Inaki Baz Castillo)

  - --- Fix pjproject compilation in certain circumstances
    (Closes issue ASTERISK-20681. Reported by Dinesh
    Ramjuttun)

For a full list of changes in this release, please see the ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-11.2.0
The Asterisk Development Team has announced a security release for
Asterisk 11, Asterisk 11.1.2. This release addresses the security
vulnerabilities reported in AST-2012-014 and AST-2012-015, and
replaces the previous version of Asterisk 11 released for these
security vulnerabilities. The prior release left open a vulnerability
in res_xmpp that exists only in Asterisk 11; as such, other versions
of Asterisk were resolved correctly by the previous releases.

This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of these versions resolve the following two issues :

  - Stack overflows that occur in some portions of Asterisk
    that manage a TCP connection. In SIP, this is
    exploitable via a remote unauthenticated session; in
    XMPP and HTTP connections, this is exploitable via
    remote authenticated sessions. The vulnerabilities in
    SIP and HTTP were corrected in a prior release of
    Asterisk; the vulnerability in XMPP is resolved in this
    release.

  - A denial of service vulnerability through exploitation
    of the device state cache. Anonymous calls had the
    capability to create devices in Asterisk that would
    never be disposed of. Handling the cachability of device
    states aggregated via XMPP is handled in this release.

These issues and their resolutions are described in the security
advisories.

For more information about the details of these vulnerabilities,
please read security advisories AST-2012-014 and AST-2012-015.

For a full list of changes in the current release, please see the
ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-11.1.2

The security advisories are available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2012-014.
    pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2012-01
      5.pdf

Thank you for your continued support of Asterisk - and we apologize
for having to do this twice!

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-014.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-015.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-11.2.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.1.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7ebc469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=891646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=891649"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-January/097760.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab374429"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"asterisk-11.2.0-1.fc18")) flag++;


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
