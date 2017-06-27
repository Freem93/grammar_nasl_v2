#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-6724.
#

include("compat.inc");

if (description)
{
  script_id(59003);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 22:53:51 $");

  script_cve_id("CVE-2012-2414", "CVE-2012-2415", "CVE-2012-2416");
  script_bugtraq_id(53205, 53206, 53210);
  script_xref(name:"FEDORA", value:"2012-6724");

  script_name(english:"Fedora 15 : asterisk-1.8.11.1-1.fc15 (2012-6724)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced security releases for
Asterisk 1.6.2, 1.8, and 10. The available security releases are
released as versions 1.6.2.24, 1.8.11.1, and 10.3.1.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk 1.6.2.24, 1.8.11.1, and 10.3.1 resolve the
following two issues :

  - A permission escalation vulnerability in Asterisk
    Manager Interface. This would potentially allow remote
    authenticated users the ability to execute commands on
    the system shell with the privileges of the user running
    the Asterisk application.

  - A heap overflow vulnerability in the Skinny Channel
    driver. The keypad button message event failed to check
    the length of a fixed length buffer before appending a
    received digit to the end of that buffer. A remote
    authenticated user could send sufficient keypad button
    message events that the buffer would be overrun.

In addition, the release of Asterisk 1.8.11.1 and 10.3.1 resolve the
following issue :

  - A remote crash vulnerability in the SIP channel driver
    when processing UPDATE requests. If a SIP UPDATE request
    was received indicating a connected line update after a
    channel was terminated but before the final destruction
    of the associated SIP dialog, Asterisk would attempt a
    connected line update on a non-existing channel, causing
    a crash.

These issues and their resolution are described in the security
advisories.

For more information about the details of these vulnerabilities,
please read security advisories AST-2012-004, AST-2012-005, and
AST-2012-006, which were released at the same time as this
announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.6.2.24
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.11.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.3.1

The security advisories are available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2012-004.
    pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2012-00
      5.pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2012-00
      6.pdf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-004.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-005.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-006.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.6.2.24
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51f14c48"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.11.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?caff1f3d"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.3.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7119338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=815762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=815766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=815774"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/079759.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6dadbe62"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC15", reference:"asterisk-1.8.11.1-1.fc15")) flag++;


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
