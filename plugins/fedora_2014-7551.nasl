#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-7551.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77768);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:40:32 $");

  script_cve_id("CVE-2014-4047");
  script_bugtraq_id(68036);
  script_xref(name:"FEDORA", value:"2014-7551");

  script_name(english:"Fedora 20 : asterisk-11.10.2-2.fc20 (2014-7551)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced security releases for
Certified Asterisk 1.8.15, 11.6, and Asterisk 1.8, 11, and 12. The
available security releases are released as versions 1.8.15-cert7,
11.6-cert4, 1.8.28.2, 11.10.2, and 12.3.2.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

These releases resolve security vulnerabilities that were previously
fixed in 1.8.15-cert6, 11.6-cert3, 1.8.28.1, 11.10.1, and 12.3.1.
Unfortunately, the fix for AST-2014-007 inadvertently introduced a
regression in Asterisk's TCP and TLS handling that prevented Asterisk
from sending data over these transports. This regression and the
security vulnerabilities have been fixed in the versions specified in
this release announcement.

The security patches for AST-2014-007 have been updated with the fix
for the regression, and are available at
http://downloads.asterisk.org/pub/security

Please note that the release of these versions resolves the following
security vulnerabilities :

  - AST-2014-005: Remote Crash in PJSIP Channel Driver's
    Publish/Subscribe Framework

  - AST-2014-006: Permission Escalation via Asterisk Manager
    User Unauthorized Shell Access

  - AST-2014-007: Denial of Service via Exhaustion of
    Allowed Concurrent HTTP Connections

  - AST-2014-008: Denial of Service in PJSIP Channel Driver
    Subscriptions

For more information about the details of these vulnerabilities,
please read security advisories AST-2014-005, AST-2014-006,
AST-2014-007, and AST-2014-008, which were released with the previous
versions that addressed these vulnerabilities.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.15-cert7
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.28.2
http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-11.6-cert4
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-11.10.2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-12.3.2

The security advisories are available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2014-005.
    pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2014-00
      6.pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2014-00
      7.pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2014-00
      8.pdf

The Asterisk Development Team has announced security releases for
Certified Asterisk 1.8.15, 11.6, and Asterisk 1.8, 11, and 12. The
available security releases are released as versions 1.8.15-cert6,
11.6-cert3, 1.8.28.1, 11.10.1, and 12.3.1.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of these versions resolves the following issue :

  - AST-2014-007: Denial of Service via Exhaustion of
    Allowed Concurrent HTTP Connections

    Establishing a TCP or TLS connection to the configured
    HTTP or HTTPS port respectively in http.conf and then
    not sending or completing a HTTP request will tie up a
    HTTP session. By doing this repeatedly until the maximum
    number of open HTTP sessions is reached, legitimate
    requests are blocked.

Additionally, the release of 11.6-cert3, 11.10.1, and 12.3.1 resolves
the following issue :

  - AST-2014-006: Permission Escalation via Asterisk Manager
    User Unauthorized Shell Access

    Manager users can execute arbitrary shell commands with
    the MixMonitor manager action. Asterisk does not require
    system class authorization for a manager user to use the
    MixMonitor action, so any manager user who is permitted
    to use manager commands can potentially execute shell
    commands as the user executing the Asterisk process.

Additionally, the release of 12.3.1 resolves the following issues :

  - AST-2014-005: Remote Crash in PJSIP Channel Driver's
    Publish/Subscribe Framework

    A remotely exploitable crash vulnerability exists in the
    PJSIP channel driver's pub/sub framework. If an attempt
    is made to unsubscribe when not currently subscribed and
    the endpoint's 'sub_min_expiry' is set to zero,
    Asterisk tries to create an expiration timer with zero
    seconds, which is not allowed, so an assertion raised.

  - AST-2014-008: Denial of Service in PJSIP Channel Driver
    Subscriptions

    When a SIP transaction timeout caused a subscription to
    be terminated, the action taken by Asterisk was
    guaranteed to deadlock the thread on which SIP requests
    are serviced. Note that this behavior could only happen
    on established subscriptions, meaning that this could
    only be exploited if an attacker bypassed authentication
    and successfully subscribed to a real resource on the
    Asterisk server.

These issues and their resolutions are described in the security
advisories.

For more information about the details of these vulnerabilities,
please read security advisories AST-2014-005, AST-2014-006,
AST-2014-007, and AST-2014-008, which were released at the same time
as this announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.15-cert6
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.28.1
http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-11.6-cert3
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-11.10.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-12.3.1

The Asterisk Development Team has announced the release of Asterisk
11.10.0. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk

The release of Asterisk 11.10.0 resolves several issues reported by
the community and would have not been possible without your
participation. Thank you!

The following are the issues resolved in this release :

Bugs fixed in this release :

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2014-005.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2014-006.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2014-007.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2014-008.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.28.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95c079df"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.28.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dca7a1f"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.10.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd99d03c"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.10.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?050e7912"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-12.3.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12bda26e"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-12.3.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c6cd6b3"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.15-cert6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98e4995b"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.15-cert7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3e371d8"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-11.6-cert3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d60d352"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-11.6-cert4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?919a96f7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1109284"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/137731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d529ac00"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"asterisk-11.10.2-2.fc20")) flag++;


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
