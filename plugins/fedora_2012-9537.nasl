#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-9537.
#

include("compat.inc");

if (description)
{
  script_id(59698);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_cve_id("CVE-2012-3553");
  script_bugtraq_id(54017);
  script_xref(name:"FEDORA", value:"2012-9537");

  script_name(english:"Fedora 17 : asterisk-10.5.1-1.fc17 (2012-9537)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced a security release for
Asterisk 10. This security release is released as version 10.5.1.

The release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk/releases

The release of Asterisk 10.5.1 resolves the following issue :

  - A remotely exploitable crash vulnerability was found in
    the Skinny (SCCP) Channel driver. When an SCCP client
    sends an Off Hook message, followed by a Key Pad Button
    Message, a structure that was previously set to NULL is
    dereferenced. This allows remote authenticated
    connections the ability to cause a crash in the server,
    denying services to legitimate users.

This issue and its resolution is described in the security advisory.

For more information about the details of this vulnerability, please
read security advisory AST-2012-009, which was released at the same
time as this announcement.

For a full list of changes in the current releases, please see the
ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLo
g-10.5.1

The security advisory is available at :

  -
    http://downloads.asterisk.org/pub/security/AST-2012-009.
    pdf

The Asterisk Development Team has announced the release of Asterisk
10.5.0. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk

The release of Asterisk 10.5.0 resolves several issues reported by the
community and would have not been possible without your participation.
Thank you!

The following is a sample of the issues resolved in this release :

  - --- Turn off warning message when bind address is set to
    any. (Closes issue ASTERISK-19456. Reported by Michael
    L. Young)

  - --- Prevent overflow in calculation in ast_tvdiff_ms on
    32-bit machines (Closes issue ASTERISK-19727. Reported
    by Ben Klang)

  - --- Make DAHDISendCallreroutingFacility wait 5 seconds
    for a reply before disconnecting the call. (Closes issue
    ASTERISK-19708. Reported by mehdi Shirazi)

  - --- Fix recalled party B feature flags for a failed DTMF
    atxfer. (Closes issue ASTERISK-19383. Reported by
    lgfsantos)

  - --- Fix DTMF atxfer running h exten after the wrong
    bridge ends. (Closes issue ASTERISK-19717. Reported by
    Mario)

For a full list of changes in this release, please see the ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-10.5.0

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2012-009.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-10.5.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk/releases"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/releases/ChangeLog-10.5.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89674f3b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=832625"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-June/082733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24fbea75"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/26");
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
if (rpm_check(release:"FC17", reference:"asterisk-10.5.1-1.fc17")) flag++;


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
