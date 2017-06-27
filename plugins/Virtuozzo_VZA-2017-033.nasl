#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100325);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/23 14:39:44 $");


  script_name(english:"Virtuozzo 7 : OVMF / anaconda / anaconda-core / anaconda-dracut / etc (VZA-2017-033)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the OVMF / anaconda / anaconda-core /
anaconda-dracut / etc packages installed, the Virtuozzo installation
on the remote host is affected by the following vulnerability :

  - A vulnerability in container resource limiting
    mechanism could potentially lead to DoS attacks.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2796982");
  script_set_attribute(attribute:"solution", value:
"Update the affected OVMF / anaconda / anaconda-core / anaconda-dracut / etc package.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:OVMF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-widgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:anaconda-widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:buse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:coripper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:cpupools-features");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:csd_firewalld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:disp-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:disp-helper-ka-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:eula-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:init-agent-ct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ksm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libcompel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libcompel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-benchmarking");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-gobject-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprl-backup-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprl-backup-compat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlxmlmodel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreport-plugin-problem-report");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libreport-plugin-virtuozzo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-driver-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-daemon-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzctl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzlic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzlic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzsock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libvzsock-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:license-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:nsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pcompact");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pdrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perccli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:pfcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:phaul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-backup-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ploop-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-backup-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disk-tool-7.0.35-");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:rmond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:shaman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:sles-11-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:spfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:storcli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ubuntu-16.04-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ubuntu-16.10-x86_64-ez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vautomator-ui-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vcmmd-policies");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-p2v-maker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virtuozzo-motd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:virtuozzo-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vmauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-aps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-chunk-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-firewall-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-libs-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-metadata-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ostor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-anaconda-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-ui-user-s3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vstorage-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-lin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-updater");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-guest-tools-win");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vz-qemu-engine-updater");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzlicutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmigrate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vztt-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/23");
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

pkgs = ["csd_firewalld-0.4-2.vz7",
        "disp-helper-0.0.36-2.vz7",
        "disp-helper-ka-plugin-0.0.3-1.vz7",
        "init-agent-ct-0.0.5-2.vz7",
        "libcompel-0.0.0.5-1.vz7",
        "libcompel-devel-0.0.0.5-1.vz7",
        "libguestfs-appliance-1.34.3-2.vz7.9.fc25",
        "libguestfs-benchmarking-1.34.3-2.vz7.9",
        "libguestfs-inspect-icons-1.34.3-2.vz7.9",
        "libreport-plugin-problem-report-1.0.7-1.vz7",
        "libvzlic-7.0.41-1.vz7",
        "libvzlic-devel-7.0.41-1.vz7",
        "nsb-0.0.6-1.vz7",
        "perccli-1.11.03-1.vz7",
        "storcli-1.21.06-1.vz7",
        "vautomator-ui-anaconda-addon-0.12-1.vz7",
        "virt-p2v-maker-1.34.3-2.vz7.9",
        "vstorage-devel-7.4.106-1.vz7",
        "vstorage-ui-1.1.63.6-3.vz7",
        "vstorage-ui-agent-1.1.62.5-1.vz7",
        "vstorage-ui-anaconda-addon-0.17-1.vz7",
        "vstorage-ui-backend-1.1.88.5-1.vz7",
        "vstorage-ui-user-s3-1.1.35.2-1.vz7",
        "vz-guest-tools-updater-1.0.24-1.vz7",
        "vz-qemu-engine-updater-0.1.14-1.vz7",
        "OVMF-20150414-2.gitc9e5618.vz7.4",
        "anaconda-21.48.22.93-1.vz7.54",
        "anaconda-core-21.48.22.93-1.vz7.54",
        "anaconda-dracut-21.48.22.93-1.vz7.54",
        "anaconda-gui-21.48.22.93-1.vz7.54",
        "anaconda-tui-21.48.22.93-1.vz7.54",
        "anaconda-widgets-21.48.22.93-1.vz7.54",
        "anaconda-widgets-devel-21.48.22.93-1.vz7.54",
        "buse-7.0.9-2.vz7",
        "coripper-1.0.4-1.vz7",
        "cpupools-7.0.12-2.vz7",
        "cpupools-features-7.0.12-2.vz7",
        "crit-2.10.0.47-1.vz7",
        "criu-2.10.0.47-1.vz7",
        "criu-devel-2.10.0.47-1.vz7",
        "eula-anaconda-addon-0.6-1.vz7",
        "ksm-vz-2.6.0-28.3.9.vz7.56",
        "libguestfs-1.34.3-2.vz7.9",
        "libguestfs-bash-completion-1.34.3-2.vz7.9",
        "libguestfs-devel-1.34.3-2.vz7.9",
        "libguestfs-gobject-1.34.3-2.vz7.9",
        "libguestfs-gobject-devel-1.34.3-2.vz7.9",
        "libguestfs-gobject-doc-1.34.3-2.vz7.9",
        "libguestfs-java-1.34.3-2.vz7.9",
        "libguestfs-java-devel-1.34.3-2.vz7.9",
        "libguestfs-javadoc-1.34.3-2.vz7.9",
        "libguestfs-man-pages-ja-1.34.3-2.vz7.9",
        "libguestfs-man-pages-uk-1.34.3-2.vz7.9",
        "libguestfs-tools-1.34.3-2.vz7.9",
        "libguestfs-tools-c-1.34.3-2.vz7.9",
        "libprl-backup-compat-7.0.5-1.vz7",
        "libprl-backup-compat-devel-7.0.5-1.vz7",
        "libprlcommon-7.0.105-1.vz7",
        "libprlcommon-devel-7.0.105-1.vz7",
        "libprlsdk-7.0.189-1.vz7",
        "libprlsdk-devel-7.0.189-1.vz7",
        "libprlsdk-headers-7.0.189-1.vz7",
        "libprlsdk-python-7.0.189-1.vz7",
        "libprlxmlmodel-7.0.64-1.vz7",
        "libprlxmlmodel-devel-7.0.64-1.vz7",
        "libreport-plugin-virtuozzo-1.0.5-1.vz7",
        "libvirt-2.4.0-1.vz7.27.1",
        "libvirt-admin-2.4.0-1.vz7.27.1",
        "libvirt-client-2.4.0-1.vz7.27.1",
        "libvirt-daemon-2.4.0-1.vz7.27.1",
        "libvirt-daemon-config-network-2.4.0-1.vz7.27.1",
        "libvirt-daemon-config-nwfilter-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-interface-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-lxc-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-network-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-nodedev-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-nwfilter-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-qemu-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-secret-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-storage-2.4.0-1.vz7.27.1",
        "libvirt-daemon-driver-vz-2.4.0-1.vz7.27.1",
        "libvirt-daemon-kvm-2.4.0-1.vz7.27.1",
        "libvirt-daemon-lxc-2.4.0-1.vz7.27.1",
        "libvirt-daemon-vz-2.4.0-1.vz7.27.1",
        "libvirt-devel-2.4.0-1.vz7.27.1",
        "libvirt-docs-2.4.0-1.vz7.27.1",
        "libvirt-libs-2.4.0-1.vz7.27.1",
        "libvirt-lock-sanlock-2.4.0-1.vz7.27.1",
        "libvirt-login-shell-2.4.0-1.vz7.27.1",
        "libvirt-nss-2.4.0-1.vz7.27.1",
        "libvzctl-7.0.371-1.vz7",
        "libvzctl-devel-7.0.371-1.vz7",
        "libvzevent-7.0.7-3.vz7",
        "libvzevent-devel-7.0.7-3.vz7",
        "libvzsock-7.0.3-1.vz7",
        "libvzsock-devel-7.0.3-1.vz7",
        "license-anaconda-addon-0.12-1.vz7",
        "lua-guestfs-1.34.3-2.vz7.9",
        "ocaml-libguestfs-1.34.3-2.vz7.9",
        "ocaml-libguestfs-devel-1.34.3-2.vz7.9",
        "pcompact-7.0.12-2.vz7",
        "pdrs-7.0.24-1.vz7",
        "perl-Sys-Guestfs-1.34.3-2.vz7.9",
        "pfcache-7.0.23-1.vz7",
        "phaul-0.1.35-1.vz7",
        "ploop-7.0.88-1.vz7",
        "ploop-backup-7.0.27-3.vz7",
        "ploop-backup-devel-7.0.27-3.vz7",
        "ploop-devel-7.0.88-1.vz7",
        "ploop-lib-7.0.88-1.vz7",
        "prl-backup-compat-7.0.5-1.vz7",
        "prl-disk-tool-7.0.35-",
        "readykernel-anaconda-addon-0.6-1.vz7",
        "rmond-7.0.7-1.vz7",
        "ruby-libguestfs-1.34.3-2.vz7.9",
        "seabios-1.9.1-5.3.2.vz7.6",
        "seabios-bin-1.9.1-5.3.2.vz7.6",
        "seavgabios-bin-1.9.1-5.3.2.vz7.6",
        "shaman-7.0.40-1.vz7",
        "sles-11-x86_64-ez-7.0.0-10.vz7",
        "spfs-0.08.024-1.vz7",
        "ubuntu-16.04-x86_64-ez-7.0.0-13.vz7",
        "ubuntu-16.10-x86_64-ez-7.0.0-3.vz7",
        "vcmmd-7.0.142-1.vz7",
        "vcmmd-policies-7.0.60-1.vz7",
        "virt-dib-1.34.3-2.vz7.9",
        "virt-v2v-1.34.3-2.vz7.9",
        "virtuozzo-motd-0.7-1.vz7",
        "virtuozzo-release-7.0.4-26.vz7",
        "vmauth-7.0.8-1.vz7",
        "vstorage-anaconda-addon-0.31-1.vz7",
        "vstorage-aps-7.4.106-1.vz7",
        "vstorage-chunk-server-7.4.106-1.vz7",
        "vstorage-client-7.4.106-1.vz7",
        "vstorage-client-devel-7.4.106-1.vz7",
        "vstorage-core-devel-7.4.106-1.vz7",
        "vstorage-ctl-7.4.106-1.vz7",
        "vstorage-firewall-cfg-7.4.106-1.vz7",
        "vstorage-iscsi-7.4.106-1.vz7",
        "vstorage-libs-shared-7.4.106-1.vz7",
        "vstorage-metadata-server-7.4.106-1.vz7",
        "vstorage-ostor-7.4.106-1.vz7",
        "vstorage-tests-7.4.106-1.vz7",
        "vstorage-www-7.4.106-1.vz7",
        "vz-docs-7.1.26-1.vz7",
        "vz-guest-tools-lin-0.10-99.vz7",
        "vz-guest-tools-win-0.49-18.vz7",
        "vzctl-7.0.148-2.vz7",
        "vzkernel-3.10.0-514.16.1.vz7.30.10",
        "vzkernel-debug-3.10.0-514.16.1.vz7.30.10",
        "vzkernel-debug-devel-3.10.0-514.16.1.vz7.30.10",
        "vzkernel-devel-3.10.0-514.16.1.vz7.30.10",
        "vzkernel-headers-3.10.0-514.16.1.vz7.30.10",
        "vzlicutils-7.0.50-4.vz7",
        "vzmigrate-7.0.64-1.vz7",
        "vzreport-7.0.13-1.vz7",
        "vzstat-7.0.13-1.vz7",
        "vztt-7.0.57-1.vz7",
        "vztt-devel-7.0.57-1.vz7",
        "vztt-lib-7.0.57-1.vz7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OVMF / anaconda / anaconda-core / anaconda-dracut / etc");
}
