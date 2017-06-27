#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-4528.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(65830);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/09 15:36:33 $");

  script_cve_id("CVE-2013-2264", "CVE-2013-2686");
  script_bugtraq_id(58756, 58764);
  script_xref(name:"FEDORA", value:"2013-4528");

  script_name(english:"Fedora 17 : asterisk-10.12.2-1.fc17 (2013-4528)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced security releases for
Certified Asterisk 1.8.15 and Asterisk 1.8, 10, and 11. The available
security releases are released as versions 1.8.15-cert2, 1.8.20.2,
10.12.2, 10.12.2-digiumphones, and 11.2.2.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of these versions resolve the following issues :

  - A possible buffer overflow during H.264 format
    negotiation. The format attribute resource for H.264
    video performs an unsafe read against a media attribute
    when parsing the SDP.

    This vulnerability only affected Asterisk 11.

  - A denial of service exists in Asterisk's HTTP server.
    AST-2012-014, fixed in January of this year, contained a
    fix for Asterisk's HTTP server for a remotely-triggered
    crash. While the fix prevented the crash from being
    triggered, a denial of service vector still exists with
    that solution if an attacker sends one or more HTTP POST
    requests with very large Content-Length values.

    This vulnerability affects Certified Asterisk 1.8.15,
    Asterisk 1.8, 10, and 11

  - A potential username disclosure exists in the SIP
    channel driver. When authenticating a SIP request with
    alwaysauthreject enabled, allowguest disabled, and
    autocreatepeer disabled, Asterisk discloses whether a
    user exists for INVITE, SUBSCRIBE, and REGISTER
    transactions in multiple ways.

    This vulnerability affects Certified Asterisk 1.8.15,
    Asterisk 1.8, 10, and 11

These issues and their resolutions are described in the security
advisories.

For more information about the details of these vulnerabilities,
please read security advisories AST-2013-001, AST-2013-002, and
AST-2013-003, which were released at the same time as this
announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.15-cert2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.20.2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.12.2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.12.2-digiumphones
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-11.2.2

The security advisories are available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2013-001.
    pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2013-00
      2.pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2013-00
      3.pdf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2013-001.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2013-002.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2013-003.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.20.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29e5303b"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.12.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4695ab6"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.12.2-digiumphones
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05ab7e1a"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.2.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16e35cb0"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.15-cert2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d97a0e84"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=928774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=928777"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-April/101684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e95e6b29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"asterisk-10.12.2-1.fc17")) flag++;


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
