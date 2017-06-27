#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97983);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");


  script_name(english:"Virtuozzo 7 : anaconda / anaconda-core / anaconda-dracut / etc (VZA-2017-012)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the anaconda / anaconda-core /
anaconda-dracut / etc packages installed, the Virtuozzo installation
on the remote host is affected by the following vulnerabilities :

  - A flaw found in the way prl-vzvncserver parsed terminal
    escape sequences that could allow a remote attacker
    authenticated with the VNC password or a user logged in
    to a container as root to execute arbitrary code as
    host root.

  - A flaw was found in prl-vzvncserver that could allow a
    remote attacker authenticated with the VNC password or
    a user logged in to a container as root to crash
    prl-vzvncserver by exploiting the way it handled
    overlapping memory areas.

  - A flaw was found in prl-vzvncserver that could allow a
    remote attacker authenticated with the VNC password or
    a user logged in to a container as root to crash
    prl-vzvncserver by executing a specially crafted
    command to overwrite a small memory region of the
    prl-vzvncserver process.

  - A flaw was found in prl-vzvncserver that could allow a
    remote attacker authenticated with the VNC password or
    a user logged in to a container as root to crash
    prl-vzvncserver by executing a specially crafted
    command to cause allocation of a huge amount of memory.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2759546");
  script_set_attribute(attribute:"solution", value:
"Update the affected anaconda / anaconda-core / anaconda-dracut / etc packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-widgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvcmmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvcmmd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pdrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pfcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-vzvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prlctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:shaman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:sles-11-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd-policies");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vmauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-aps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-chunk-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-firewall-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-libs-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-metadata-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ostor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-win");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzlicutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmigrate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = eregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["sles-11-x86_64-ez-7.0.0-9.vz7",
        "vmauth-7.0.5-1.vz7",
        "anaconda-21.48.22.93-1.vz7.7.3",
        "anaconda-core-21.48.22.93-1.vz7.7.3",
        "anaconda-dracut-21.48.22.93-1.vz7.7.3",
        "anaconda-gui-21.48.22.93-1.vz7.7.3",
        "anaconda-tui-21.48.22.93-1.vz7.7.3",
        "anaconda-widgets-21.48.22.93-1.vz7.7.3",
        "anaconda-widgets-devel-21.48.22.93-1.vz7.7.3",
        "libprlcommon-7.0.90-1.vz7",
        "libprlcommon-devel-7.0.90-1.vz7",
        "libprlsdk-7.0.169.5-1.vz7",
        "libprlsdk-devel-7.0.169.5-1.vz7",
        "libprlsdk-headers-7.0.169.5-1.vz7",
        "libprlsdk-python-7.0.169.5-1.vz7",
        "libprlxmlmodel-7.0.55-1.vz7",
        "libprlxmlmodel-devel-7.0.55-1.vz7",
        "libvcmmd-7.0.21-1.vz7",
        "libvcmmd-devel-7.0.21-1.vz7",
        "libvzctl-7.0.333.15-2.vz7",
        "libvzctl-devel-7.0.333.15-2.vz7",
        "pdrs-7.0.22-1.vz7",
        "pfcache-7.0.20-12.vz7",
        "prl-disp-backup-7.0.36-7.vz7",
        "prl-disp-legacy-7.0.587.19-1.vz7",
        "prl-disp-service-7.0.587.19-1.vz7",
        "prl-disp-service-tests-7.0.587.19-1.vz7",
        "prl-vzvncserver-7.0.8-1.vz7",
        "prlctl-7.0.108-1.vz7",
        "shaman-7.0.27-6.vz7",
        "vcmmd-7.0.130.6-1.vz7",
        "vcmmd-policies-7.0.53-1.vz7",
        "vstorage-anaconda-addon-0.19-1.vz7",
        "vstorage-aps-7.3.254-6.vz7",
        "vstorage-chunk-server-7.3.254-6.vz7",
        "vstorage-client-7.3.254-6.vz7",
        "vstorage-client-devel-7.3.254-6.vz7",
        "vstorage-core-devel-7.3.254-6.vz7",
        "vstorage-ctl-7.3.254-6.vz7",
        "vstorage-firewall-cfg-7.3.254-6.vz7",
        "vstorage-iscsi-7.3.254-6.vz7",
        "vstorage-libs-shared-7.3.254-6.vz7",
        "vstorage-metadata-server-7.3.254-6.vz7",
        "vstorage-ostor-7.3.254-6.vz7",
        "vstorage-tests-7.3.254-6.vz7",
        "vstorage-www-7.3.254-6.vz7",
        "vz-guest-tools-win-0.48-7.vz7",
        "vzctl-7.0.138.4-1.vz7",
        "vzlicutils-7.0.39-9.vz7",
        "vzmigrate-7.0.53-1.vz7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "anaconda / anaconda-core / anaconda-dracut / etc");
}
