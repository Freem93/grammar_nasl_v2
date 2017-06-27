#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-10324.
#

include("compat.inc");

if (description)
{
  script_id(60069);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:27:57 $");

  script_cve_id("CVE-2012-3812", "CVE-2012-3863");
  script_bugtraq_id(54317, 54327);
  script_xref(name:"FEDORA", value:"2012-10324");

  script_name(english:"Fedora 17 : asterisk-10.5.2-1.fc17 (2012-10324)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced security releases for
Certified Asterisk 1.8.11 and Asterisk 1.8 and 10. The available
security releases are released as versions 1.8.11-cert4, 1.8.13.1,
10.5.2, and 10.5.2-digiumphones.

These releases are available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk 1.8.11-cert4, 1.8.13.1, 10.5.2, and
10.5.2-digiumphones resolve the following two issues :

  - If Asterisk sends a re-invite and an endpoint responds
    to the re-invite with a provisional response but never
    sends a final response, then the SIP dialog structure is
    never freed and the RTP ports for the call are never
    released. If an attacker has the ability to place a
    call, they could create a denial of service by using all
    available RTP ports.

  - If a single voicemail account is manipulated by two
    parties simultaneously, a condition can occur where
    memory is freed twice causing a crash.

These issues and their resolution are described in the security
advisories.

For more information about the details of these vulnerabilities,
please read security advisories AST-2012-010 and AST-2012-011, which
were released at the same time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLogs :

http://downloads.asterisk.org/pub/telephony/certified-asterisk/release
s/ChangeLog-1.8.11-cert4
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-1.8.13.1
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.5.2
http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.5.2-digiumphones

The security advisories are available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2012-010.
    pdf

    -
      http://downloads.asterisk.org/pub/security/AST-2012-01
      1.pdf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-010.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-011.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-1.8.13.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?018f28b9"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.5.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a7457b9"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.5.2-digiumphones
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b73d250"
  );
  # http://downloads.asterisk.org/pub/telephony/certified-asterisk/releases/ChangeLog-1.8.11-cert4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07969e81"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=838178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=838179"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-July/084037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0d3841c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC17", reference:"asterisk-10.5.2-1.fc17")) flag++;


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
