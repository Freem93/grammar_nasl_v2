#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97977);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");


  script_name(english:"Virtuozzo 6 : libvzctl / parallels-kernel-modules / etc (VZA-2017-005)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libvzctl / parallels-kernel-modules
/ etc packages installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

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
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2749696");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvzctl / parallels-kernel-modules / etc packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-reconfiguration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bm-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-transporter-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vi-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-vzvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-virtualization-sdk-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-parallels-virtualization-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzctl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["libvzctl-6.0.12-145",
        "parallels-kernel-modules-6.12.26067.1232382-1.el6",
        "parallels-reconfiguration-6.12.26067.1232382-1",
        "parallels-server-6.12.26067.1232382-1.el6",
        "parallels-server-bios-6.12.26067.1232382-1.el6",
        "parallels-server-bm-release-6.0.12-3670",
        "parallels-server-cli-6.12.26067.1232382-1.el6",
        "parallels-server-docs-6.12.26067.1232382-1.el6.el6",
        "parallels-server-efi-6.12.26067.1232382-1.el6",
        "parallels-server-lib-6.12.26067.1232382-1.el6",
        "parallels-server-transporter-agents-6.12.26067.1232382-1.el6",
        "parallels-server-vi-cli-6.12.26067.1232382-1.el6",
        "parallels-server-vmm-6.12.26067.1232382-1.el6",
        "parallels-server-vncserver-6.12.26067.1232382-1.el6",
        "parallels-server-vzvncserver-6.12.26067.1232382-1.el6",
        "parallels-virtualization-sdk-6.12.26067.1232382-1.el6",
        "parallels-virtualization-sdk-devel-6.12.26067.1232382-1.el6",
        "parallels-virtualization-sdk-docs-6.12.26067.1232382-1.el6",
        "parallels-web-6.12.26067.1232382-1",
        "python-parallels-virtualization-sdk-6.12.26067.1232382-1.el6",
        "vzctl-6.0.12-426",
        "vzctl-lib-6.0.12-426",
        "vztt-6.0.12-72",
        "vztt-build-6.0.12-72",
        "vztt-lib-6.0.12-72"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvzctl / parallels-kernel-modules / etc");
}
