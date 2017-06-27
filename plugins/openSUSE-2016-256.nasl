#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-256.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88927);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2016-0723", "CVE-2016-2069");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-256)");
  script_summary(english:"Check for the openSUSE-2016-256 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.2 kernel was updated to receive security and bugfixes.

It also fixes a regression that caused the Chromium sandbox to no
longer work (bsc#965356).

Following security bugs were fixed :

  - CVE-2016-2069: A flaw was discovered in a way the Linux
    deals with paging structures. When Linux invalidates a
    paging structure that is not in use locally, it could,
    in principle, race against another CPU that is switching
    to a process that uses the paging structure in question,
    causing a local denial service (machine crash).
    (bnc#963767).

  - CVE-2016-0723: Race condition in the tty_ioctl function
    in drivers/tty/tty_io.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (use-after-free and
    system crash) by making a TIOCGETD ioctl call during
    processing of a TIOCSETD ioctl call (bnc#961500).

The following non-security bugs were fixed :

  - Bluetooth: ath3k: workaround the compatibility issue
    with xHCI controller (bnc#907378).

  - kABI fix for addition of user_namespace.flags field
    (bnc#965308, bnc#965356).

  - userns: Add a knob to disable setgroups on a per user
    namespace basis (bnc#965308, bnc#965356).

  - userns: Allow setting gid_maps without privilege when
    setgroups is disabled (bnc#965308, bnc#965356).

  - userns: Rename id_map_mutex to userns_state_mutex
    (bnc#965308, bnc#965356)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965356"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-0.8-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-debugsource-0.8-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-0.8_k3.16.7_35-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-debuginfo-0.8_k3.16.7_35-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-0.8_k3.16.7_35-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-debuginfo-0.8_k3.16.7_35-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-0.8_k3.16.7_35-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-debuginfo-0.8_k3.16.7_35-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-0.8_k3.16.7_35-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-debuginfo-0.8_k3.16.7_35-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-2.639-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debuginfo-2.639-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debugsource-2.639-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-2.639_k3.16.7_35-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-debuginfo-2.639_k3.16.7_35-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-2.639_k3.16.7_35-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.16.7_35-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-2.639_k3.16.7_35-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-debuginfo-2.639_k3.16.7_35-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-2.639_k3.16.7_35-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-debuginfo-2.639_k3.16.7_35-14.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-7.0.8-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debuginfo-7.0.8-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debugsource-7.0.8-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-devel-7.0.8-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-7.0.8-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-debuginfo-7.0.8-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-7.0.8-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-debuginfo-7.0.8-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-7.0.8_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-debuginfo-7.0.8_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-7.0.8_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-debuginfo-7.0.8_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-7.0.8_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-debuginfo-7.0.8_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-7.0.8_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-debuginfo-7.0.8_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-debugsource-1.28-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-1.28_k3.16.7_35-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.16.7_35-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-1.28_k3.16.7_35-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.16.7_35-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-1.28_k3.16.7_35-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.16.7_35-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-1.28_k3.16.7_35-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.16.7_35-18.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-6.23-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debuginfo-6.23-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debugsource-6.23-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-devel-6.23-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-6.23_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-debuginfo-6.23_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-6.23_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-debuginfo-6.23_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-6.23_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-debuginfo-6.23_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-6.23_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-debuginfo-6.23_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-macros-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-3.16.7-35.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-debugsource-3.16.7-35.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-xen-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-vanilla-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-syms-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-6.23-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-debuginfo-6.23-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-0.44-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debuginfo-0.44-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debugsource-0.44-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-0.44_k3.16.7_35-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.16.7_35-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-0.44_k3.16.7_35-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.16.7_35-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-0.44_k3.16.7_35-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.16.7_35-260.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-debugsource-20140629-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-20140629_k3.16.7_35-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-debuginfo-20140629_k3.16.7_35-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-20140629_k3.16.7_35-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-debuginfo-20140629_k3.16.7_35-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-20140629_k3.16.7_35-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-debuginfo-20140629_k3.16.7_35-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-20140629_k3.16.7_35-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-debuginfo-20140629_k3.16.7_35-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-4.3.36_k3.16.7_35-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-source-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-4.3.36-43.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-debugsource-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-devel-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-debuginfo-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-debuginfo-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-2.6-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debuginfo-2.6-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debugsource-2.6-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-2.6_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-debuginfo-2.6_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-2.6_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-debuginfo-2.6_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-2.6_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-debuginfo-2.6_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-2.6_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-debuginfo-2.6_k3.16.7_35-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-devel-3.16.7-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-doc-html-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-4.4.3_08_k3.16.7_35-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.3_08_k3.16.7_35-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-4.4.3_08_k3.16.7_35-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-debuginfo-4.4.3_08_k3.16.7_35-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-32bit-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-4.4.3_08-40.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.3_08-40.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bbswitch / bbswitch-debugsource / bbswitch-kmp-default / etc");
}
