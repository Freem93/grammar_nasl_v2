#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-8eac23007d.
#

include("compat.inc");

if (description)
{
  script_id(99413);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/17 14:16:27 $");

  script_cve_id("CVE-2017-6967");
  script_xref(name:"FEDORA", value:"2017-8eac23007d");

  script_name(english:"Fedora 24 : 1:xrdp / xorgxrdp (2017-8eac23007d)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New upstream version of xorgxrdp and xrdp :

New features in xrdp :

  - RemoteFX codec support is now enabled by default.

  - Bitmap updates support is now enabled by default.

  - TLS ciphers suites and version is now logged.

  - Connected computer name is now logged.

  - Switched to Xorg (xorgxrdp) as the default backend now.

  - Miscellaneous RemoteFX codec mode improvements.

  - Socket directory is configurable at the compile time.

Bugfixes in xrdp :

  - Parallels client for MacOS / iOS can now connect (audio
    redirection must be disabled on client or xrdp server
    though).

  - MS RDP client for iOS can now connect using TLS security
    layer.

  - MS RDP client for Android can now connect to xrdp.

  - Large resolutions (4K) can be used with RemoteFX
    graphics.

  - Multiple RemoteApps can be opened throguh NeutrinoRDP
    proxy.

  - tls_ciphers in xrdp.ini is not limited to 63 chars
    anymore, it's variable-length.

  - Fixed an issue where tls_ciphers were ignored and rdp
    security layer could be used instead.

  - Kill disconnected sessions feature is working with Xorg
    (xorgxrdp) backend.

  - Miscellaneous code cleanup and memory issues fixes.

Rebuild of xrdp requiring both xorgxrdp and tigervnc-minimal. VNC is
still the default.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-8eac23007d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 1:xrdp and / or xorgxrdp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:xrdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorgxrdp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/17");
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
if (rpm_check(release:"FC24", reference:"xrdp-0.9.2-5.fc24", epoch:"1")) flag++;
if (rpm_check(release:"FC24", reference:"xorgxrdp-0.2.1-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:xrdp / xorgxrdp");
}
