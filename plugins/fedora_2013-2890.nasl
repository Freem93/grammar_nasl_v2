#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-2890.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64983);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_cve_id("CVE-2012-5621");
  script_bugtraq_id(56790);
  script_xref(name:"FEDORA", value:"2013-2890");

  script_name(english:"Fedora 17 : ekiga-4.0.1-1.fc17 / opal-3.10.10-1.fc17 / ptlib-2.10.10-1.fc17 (2013-2890)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New upstream ekiga 4.0.1 release

  - Core fixes

    - Fix crash when quitting ekiga while receiving presence
      information

    - Fix crash when quitting ekiga right after starting it
      (before STUN ending)

    - Fix crash when disabling an account while icons in
      roster are changing

    - Fix crash when receiving call a second time

    - Fix crash in XML parsing in case of malicious code
      (CVE-2012-5621)

    - Fix increasing CPU usage after hours of usage caused
      by endless OPTIONS

    - Several fixes for H.323 :

    - fix H.323 parsing

    - add the username in authentication

    - fix unregistering the gatekeeper

    - fix registration

    - assign gk_name only if success

    - do not propose adding an H.323 account if the protocol
      is not built-in

    - Fix registration for registrars accepting the last
      Contact item offered

    - Allow to change the REGISTER compatibility mode of an
      existing registration

    - Fix impossibility to hangup active call after a missed
      call

    - Fix busy or call forwarding on busy occuring when
      connection is released

    - Fix subscribing/unsubscribing when enabling and
      disabling SIP accounts

    - Do not show is-typing messages sent by other programs
      during chatting

    - Stop ongoing registration when remove account

    - Use meaningful names for ALSA sub-devices

    - Allow to enter contact addresses without host part,
      and choose the host later

    - Increase number of characters shown in device names

    - Use a better icon for call history in addressbook

    - Show the address instead of 'telephoneNumber' in
      addressbook

    - Deactivate NullAudio ptlib's device for audio input
      too

    - Do not send OPTIONS messages once the account is
      disabled

    - Hide the main window immediately on exit

    - Handle xa status as away

    - Fix debugging message when registering

    - Fix race condition leading to duplicate entry in call
      history

    - Fix incoming call if two INVITE's in a fork arrive
      very close together

    - Use correct username in OPTIONS messages

    - Allow to have message waiting indication even if
      asterisk's vmexten is off

    - Send OPTION only on the right interface

    - Fix buttons direction in dialpad for RTL languages

    - Fix aborting RTP receiver with Polycom HDX8000

    - Fix possible incorrect jitter calculation for RTCP

    - Only kill REGISTER/SUBSCRIBE forks if a 'try again'
      response is received

    - Various other fixes

    - Distributor-visible changes

    - Build fixes

    - Fix building opal when java SDK installed and swig is
      not

    - Some code cleanup

    - Translation updates

    - Update translations: fr, ml, pt_BR

    - Update help translations: pt_BR

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=883058"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-March/099570.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6b56499"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-March/099571.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2eeeefa0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-March/099572.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43429d55"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ekiga, opal and / or ptlib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ekiga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:opal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ptlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/04");
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
if (rpm_check(release:"FC17", reference:"ekiga-4.0.1-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"opal-3.10.10-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"ptlib-2.10.10-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ekiga / opal / ptlib");
}
