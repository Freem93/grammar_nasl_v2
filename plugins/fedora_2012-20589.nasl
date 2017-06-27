#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-20589.
#

include("compat.inc");

if (description)
{
  script_id(63496);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 15:27:59 $");

  script_cve_id("CVE-2012-5642");
  script_bugtraq_id(56963);
  script_xref(name:"FEDORA", value:"2012-20589");

  script_name(english:"Fedora 18 : fail2ban-0.8.8-1.fc18 (2012-20589)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 0.8.8 (CVE-2012-5642 Bug #887914)

  - Fixes :

    - Alan Jenkins

    - [8c38907] Removed 'POSSIBLE BREAK-IN ATTEMPT' from
      sshd filter to avoid banning due to misconfigured DNS.
      Close gh-64

  - Yaroslav Halchenko

    - [83109bc] IMPORTANT: escape the content of <matches>
      (if used in custom action files) since its value could
      contain arbitrary symbols. Thanks for discovery go to
      the NBS System security team

  - [b159eab] do not enable pyinotify backend if pyinotify <
    0.8.3

    - [37a2e59] store IP as a base, non-unicode str to avoid
      spurious messages in the console. Close gh-91

  - New features :

    - David Engeset

    - [2d672d1,6288ec2] 'unbanip' command for the client +
      avoidance of touching the log file to take 'banip' or
      'unbanip' in effect. Close gh-81, gh-86

  - Yaroslav Halchenko

    - Enhancements :

    - [2d66f31] replaced uninformative 'Invalid command'
      message with warning log exception why command
      actually failed

  - [958a1b0] improved failregex to 'support' auth.backend =
    'htdigest'

    - [9e7a3b7] until we make it proper module -- adjusted
      sys.path only if system-wide run

  - [f52ba99] downgraded 'already banned' from WARN to INFO
    level. Closes gh-79

    - [f105379] added hints into the log on some failure
      return codes (e.g. 0x7f00 for this gh-87)

  - Various others: travis-ci integration, script to run
    tests against all available Python versions, etc

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=887914"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-January/095933.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f45b7018"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fail2ban package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fail2ban");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/14");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"fail2ban-0.8.8-1.fc18")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fail2ban");
}
