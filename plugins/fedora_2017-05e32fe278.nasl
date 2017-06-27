#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-05e32fe278.
#

include("compat.inc");

if (description)
{
  script_id(97500);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/03 14:52:26 $");

  script_cve_id("CVE-2013-1430");
  script_xref(name:"FEDORA", value:"2017-05e32fe278");

  script_name(english:"Fedora 24 : 1:xrdp (2017-05e32fe278)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"WARNING: Please note that this update comes with a slightly different
syntax of sesman.ini file, so if you edited this file by hand, you may
need to look at the .rpmnew file and merge any required changes by
hand.

This release also creates three files in /etc/xrdp directory if they
don't already exist or are empty :

  - rsakeys.ini

  - cert.pem

  - key.pem

Also note that in Fedora, the only backend that will really work is
still Xvnc for now.

New features

  - New xorgxrdp backend using existing Xorg with additional
    modules

  - Improvements to X11rdp backend

  - Support for IPv6 (disabled by default)

  - Initial support for RemoteFX Codec (disabled by default)

  - Support for TLS security layer (preferred over RDP layer
    if supported by the client)

  - Support for disabling deprecated SSLv3 protocol and for
    selecting custom cipher suites in xrdp.ini

  - Support for bidirectional fastpath (enabled in both
    directions by default)

  - Support clients that don't support drawing orders, such
    as MS RDP client for Android, ChromeRDP (disabled by
    default)

  - More configurable login screen

  - Support for new virtual channels :

    - rdpdr: device redirection

    - rdpsnd: audio output

    - cliprdr: clipboard

    - xrdpvr: xrdp video redirection channel (can be used
      along with NeutrinoRDP client)

  - Support for disabling virtual channels globally or by
    session type

  - Allow to specify the path for backends (Xorg, X11rdp,
    Xvnc)

  - Added files for systemd support

  - Multi-monitor support

  - xrdp-chansrv stroes logs in ${XDG_DATA_HOME}/xrdp now

Security fixes

  - User's password could be recovered from the Xvnc
    password file

  - X11 authentication was not used

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-05e32fe278"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 1:xrdp package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:xrdp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"xrdp-0.9.1-5.fc24", epoch:"1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:xrdp");
}
