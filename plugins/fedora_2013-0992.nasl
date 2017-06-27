#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-0992.
#

include("compat.inc");

if (description)
{
  script_id(64369);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/19 21:02:56 $");

  script_cve_id("CVE-2012-5976", "CVE-2012-5977");
  script_xref(name:"FEDORA", value:"2013-0992");

  script_name(english:"Fedora 16 : asterisk-1.8.20.0-1.fc16 (2013-0992)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Asterisk Development Team has announced the release of Asterisk
1.8.20.0. This release is available for immediate download at
http://downloads.asterisk.org/pub/telephony/asterisk

The release of Asterisk 1.8.20.0 resolves several issues reported by
the community and would have not been possible without your
participation. Thank you!

The following is a sample of the issues resolved in this release :

  - --- app_meetme: Fix channels lingering when hung up
    under certain conditions (Closes issue ASTERISK-20486.
    Reported by Michael Cargile)

  - --- Fix stuck DTMF when bridge is broken. (Closes issue
    ASTERISK-20492. Reported by Jeremiah Gowdy)

  - --- Improve Code Readability And Fix Setting natdetected
    Flag (Closes issue ASTERISK-20724. Reported by Michael
    L. Young)

  - --- Fix extension matching with the '-' char. (Closes
    issue ASTERISK-19205. Reported by Philippe Lindheimer,
    Birger 'WIMPy' Harzenetter)

  - --- Fix call files when astspooldir is relative. (Closes
    issue ASTERISK-20593. Reported by James Le Cuirot)

For a full list of changes in this release, please see the ChangeLog :

http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.8.20.
0

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/telephony/asterisk"
  );
  # http://downloads.asterisk.org/pub/telephony/asterisk/ChangeLog-1.8.20.0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba8b1513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=891646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=891649"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-January/097815.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66dfcde1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected asterisk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:asterisk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"asterisk-1.8.20.0-1.fc16")) flag++;


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
