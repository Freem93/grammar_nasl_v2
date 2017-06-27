#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-13399.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78804);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/18 16:42:52 $");

  script_cve_id("CVE-2014-3566");
  script_xref(name:"FEDORA", value:"2014-13399");

  script_name(english:"Fedora 21 : asterisk-11.13.1-1.fc21 (2014-13399) (POODLE)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Oct 20 2014 Jeffrey C. Ollie <jeff at ocjtech.us> -
    11.13.1-1 The Asterisk Development Team has announced
    security releases for Certified Asterisk 1.8.28 and 11.6
    and Asterisk 1.8, 11, 12, and 13. The available security
    releases are released as versions 1.8.28-cert2,
    11.6-cert7, 1.8.31.1, 11.13.1, 12.6.1, and 13.0.0-beta3.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of these versions resolves the following security
vulnerability :

  - AST-2014-011: Asterisk Susceptibility to POODLE
    Vulnerability

    Asterisk is susceptible to the POODLE vulnerability in
    two ways: 1) The res_jabber and res_xmpp module both use
    SSLv3 exclusively for their encrypted connections. 2)
    The core TLS handling in Asterisk, which is used by the
    chan_sip channel driver, Asterisk Manager Interface
    (AMI), and Asterisk HTTP Server, by default allow a TLS
    connection to fallback to SSLv3. This allows for a MITM
    to potentially force a connection to fallback to SSLv3,
    exposing it to the POODLE vulnerability.

    These issues have been resolved in the versions released
    in conjunction with this security advisory.

For more information about the details of this vulnerability, please
read security advisory AST-2014-011, which was released at the same
time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.28-cert2
http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-11.6-cert7
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.31.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-11.13.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-12.6.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-13.0.0-beta3

The security advisory is available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2014-011.
    pdf

  - Mon Oct 20 2014 Jeffrey C. Ollie <jeff at ocjtech.us> -
    11.13.0-1 The Asterisk Development Team has announced
    the release of Asterisk 11.13.0. This release is
    available for immediate download at
    http://downloads.asterisk.org/pub/telephony/asterisk

The release of Asterisk 11.13.0 resolves several issues reported by
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
    value:"http://downloads.asterisk.org/pub/security/AST-2014-011.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.31.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37c37e48"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-11.13.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31a540f8"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-12.6.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8aaea28d"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-13.0.0-beta3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3d5c3c6"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.28-cert2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a2f1c54"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-11.6-cert7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fe11d8f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1154894"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/142089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?344079a1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"asterisk-11.13.1-1.fc21")) flag++;


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
