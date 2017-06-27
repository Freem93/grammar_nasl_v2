#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-543.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85432);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/17 13:58:23 $");

  script_cve_id("CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-1420", "CVE-2015-1465", "CVE-2015-2041", "CVE-2015-2922", "CVE-2015-3212", "CVE-2015-3290", "CVE-2015-3339", "CVE-2015-3636", "CVE-2015-4001", "CVE-2015-4002", "CVE-2015-4003", "CVE-2015-4036", "CVE-2015-4167", "CVE-2015-4692", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2015-543)");
  script_summary(english:"Check for the openSUSE-2015-543 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.2 kernel was updated to receive various security and
bugfixes.

Following security bugs were fixed :

  - CVE-2015-3290: A flaw was found in the way the Linux
    kernels nested NMI handler and espfix64 functionalities
    interacted during NMI processing. A local, unprivileged
    user could use this flaw to crash the system or,
    potentially, escalate their privileges on the system.

  - CVE-2015-3212: A race condition flaw was found in the
    way the Linux kernels SCTP implementation handled
    Address Configuration lists when performing Address
    Configuration Change (ASCONF). A local attacker could
    use this flaw to crash the system via a race condition
    triggered by setting certain ASCONF options on a socket.

  - CVE-2015-5364: A remote denial of service (hang) via UDP
    flood with incorrect package checksums was fixed.
    (bsc#936831).

  - CVE-2015-5366: A remote denial of service (unexpected
    error returns) via UDP flood with incorrect package
    checksums was fixed. (bsc#936831).

  - CVE-2015-4700: A local user could have created a bad
    instruction in the JIT processed BPF code, leading to a
    kernel crash (bnc#935705).

  - CVE-2015-1420: Race condition in the handle_to_path
    function in fs/fhandle.c in the Linux kernel allowed
    local users to bypass intended size restrictions and
    trigger read operations on additional memory locations
    by changing the handle_bytes value of a file handle
    during the execution of this function (bnc#915517).

  - CVE-2015-4692: The kvm_apic_has_events function in
    arch/x86/kvm/lapic.h in the Linux kernel allowed local
    users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact by leveraging /dev/kvm access
    for an ioctl call (bnc#935542).

  - CVE-2015-4167 CVE-2014-9728 CVE-2014-9730 CVE-2014-9729
    CVE-2014-9731: Various problems in the UDF filesystem
    were fixed that could lead to crashes when mounting
    prepared udf filesystems.

  - CVE-2015-4002: drivers/staging/ozwpan/ozusbsvc1.c in the
    OZWPAN driver in the Linux kernel did not ensure that
    certain length values are sufficiently large, which
    allowed remote attackers to cause a denial of service
    (system crash or large loop) or possibly execute
    arbitrary code via a crafted packet, related to the (1)
    oz_usb_rx and (2) oz_usb_handle_ep_data functions
    (bnc#933934).

  - CVE-2015-4003: The oz_usb_handle_ep_data function in
    drivers/staging/ozwpan/ozusbsvc1.c in the OZWPAN driver
    in the Linux kernel allowed remote attackers to cause a
    denial of service (divide-by-zero error and system
    crash) via a crafted packet (bnc#933934).

  - CVE-2015-4001: Integer signedness error in the
    oz_hcd_get_desc_cnf function in
    drivers/staging/ozwpan/ozhcd.c in the OZWPAN driver in
    the Linux kernel allowed remote attackers to cause a
    denial of service (system crash) or possibly execute
    arbitrary code via a crafted packet (bnc#933934).

  - CVE-2015-4036: A potential memory corruption in
    vhost/scsi was fixed.

  - CVE-2015-2922: The ndisc_router_discovery function in
    net/ipv6/ndisc.c in the Neighbor Discovery (ND) protocol
    implementation in the IPv6 stack in the Linux kernel
    allowed remote attackers to reconfigure a hop-limit
    setting via a small hop_limit value in a Router
    Advertisement (RA) message (bnc#922583).

  - CVE-2015-3636: It was found that the Linux kernels ping
    socket implementation did not properly handle socket
    unhashing during spurious disconnects, which could lead
    to a use-after-free flaw. On x86-64 architecture
    systems, a local user able to create ping sockets could
    use this flaw to crash the system. On non-x86-64
    architecture systems, a local user able to create ping
    sockets could use this flaw to escalate their privileges
    on the system.

  - CVE-2015-2041: net/llc/sysctl_net_llc.c in the Linux
    kernel used an incorrect data type in a sysctl table,
    which allowed local users to obtain potentially
    sensitive information from kernel memory or possibly
    have unspecified other impact by accessing a sysctl
    entry (bnc#919007).

  - CVE-2015-3339: Race condition in the prepare_binprm
    function in fs/exec.c in the Linux kernel allowed local
    users to gain privileges by executing a setuid program
    at a time instant when a chown to root is in progress,
    and the ownership is changed but the setuid bit is not
    yet stripped.

  - CVE-2015-1465: The IPv4 implementation in the Linux
    kernel did not properly consider the length of the
    Read-Copy Update (RCU) grace period for redirecting
    lookups in the absence of caching, which allowed remote
    attackers to cause a denial of service (memory
    consumption or system crash) via a flood of packets
    (bnc#916225).

The following non-security bugs were fixed :

  - ALSA: ak411x: Fix stall in work callback (boo#934755).

  - ALSA: emu10k1: Emu10k2 32 bit DMA mode (boo#934755).

  - ALSA: emu10k1: Fix card shortname string buffer overflow
    (boo#934755).

  - ALSA: emu10k1: do not deadlock in proc-functions
    (boo#934755).

  - ALSA: emux: Fix mutex deadlock at unloading
    (boo#934755).

  - ALSA: emux: Fix mutex deadlock in OSS emulation
    (boo#934755).

  - ALSA: hda - Add AZX_DCAPS_SNOOP_OFF (and refactor snoop
    setup) (boo#934755).

  - ALSA: hda - Add Conexant codecs CX20721, CX20722,
    CX20723 and CX20724 (boo#934755).

  - ALSA: hda - Add common pin macros for ALC269 family
    (boo#934755).

  - ALSA: hda - Add dock support for ThinkPad X250
    (17aa:2226) (boo#934755).

  - ALSA: hda - Add dock support for Thinkpad T450s
    (17aa:5036) (boo#934755).

  - ALSA: hda - Add headphone quirk for Lifebook E752
    (boo#934755).

  - ALSA: hda - Add headset mic quirk for Dell Inspiron 5548
    (boo#934755).

  - ALSA: hda - Add mute-LED mode control to Thinkpad
    (boo#934755).

  - ALSA: hda - Add one more node in the EAPD supporting
    candidate list (boo#934755).

  - ALSA: hda - Add pin configs for ASUS mobo with IDT
    92HD73XX codec (boo#934755).

  - ALSA: hda - Add ultra dock support for Thinkpad X240
    (boo#934755).

  - ALSA: hda - Add workaround for CMI8888 snoop behavior
    (boo#934755).

  - ALSA: hda - Add workaround for MacBook Air 5,2 built-in
    mic (boo#934755).

  - ALSA: hda - Disable runtime PM for Panther Point again
    (boo#934755).

  - ALSA: hda - Do not access stereo amps for mono channel
    widgets (boo#934755).

  - ALSA: hda - Fix Dock Headphone on Thinkpad X250 seen as
    a Line Out (boo#934755).

  - ALSA: hda - Fix headphone pin config for Lifebook T731
    (boo#934755).

  - ALSA: hda - Fix noise on AMD radeon 290x controller
    (boo#934755).

  - ALSA: hda - Fix probing and stuttering on CMI8888
    HD-audio controller (boo#934755).

  - ALSA: hda - One more Dell macine needs
    DELL1_MIC_NO_PRESENCE quirk (boo#934755).

  - ALSA: hda - One more HP machine needs to change mute led
    quirk (boo#934755).

  - ALSA: hda - Set GPIO 4 low for a few HP machines
    (boo#934755).

  - ALSA: hda - Set single_adc_amp flag for CS420x codecs
    (boo#934755).

  - ALSA: hda - Treat stereo-to-mono mix properly
    (boo#934755).

  - ALSA: hda - change three SSID quirks to one pin quirk
    (boo#934755).

  - ALSA: hda - fix 'num_steps = 0' error on ALC256
    (boo#934755).

  - ALSA: hda - fix a typo by changing mute_led_nid to
    cap_mute_led_nid (boo#934755).

  - ALSA: hda - fix headset mic detection problem for one
    more machine (boo#934755).

  - ALSA: hda - fix mute led problem for three HP laptops
    (boo#934755).

  - ALSA: hda - set proper caps for newer AMD hda audio in
    KB/KV (boo#934755).

  - ALSA: hda/realtek - ALC292 dock fix for Thinkpad L450
    (boo#934755).

  - ALSA: hda/realtek - Add a fixup for another Acer Aspire
    9420 (boo#934755).

  - ALSA: hda/realtek - Enable the ALC292 dock fixup on the
    Thinkpad T450 (boo#934755).

  - ALSA: hda/realtek - Fix Headphone Mic does not recording
    for ALC256 (boo#934755).

  - ALSA: hda/realtek - Make more stable to get pin sense
    for ALC283 (boo#934755).

  - ALSA: hda/realtek - Support Dell headset mode for ALC256
    (boo#934755).

  - ALSA: hda/realtek - Support HP mute led for output and
    input (boo#934755).

  - ALSA: hda/realtek - move HP_LINE1_MIC1_LED quirk for
    alc282 (boo#934755).

  - ALSA: hda/realtek - move HP_MUTE_LED_MIC1 quirk for
    alc282 (boo#934755).

  - ALSA: hdspm - Constrain periods to 2 on older cards
    (boo#934755).

  - ALSA: pcm: Do not leave PREPARED state after draining
    (boo#934755).

  - ALSA: snd-usb: add quirks for Roland UA-22 (boo#934755).

  - ALSA: usb - Creative USB X-Fi Pro SB1095 volume knob
    support (boo#934755).

  - ALSA: usb-audio: Add mic volume fix quirk for Logitech
    Quickcam Fusion (boo#934755).

  - ALSA: usb-audio: Add quirk for MS LifeCam HD-3000
    (boo#934755).

  - ALSA: usb-audio: Add quirk for MS LifeCam Studio
    (boo#934755).

  - ALSA: usb-audio: Do not attempt to get Lifecam HD-5000
    sample rate (boo#934755).

  - ALSA: usb-audio: Do not attempt to get Microsoft Lifecam
    Cinema sample rate (boo#934755).

  - ALSA: usb-audio: add MAYA44 USB+ mixer control names
    (boo#934755).

  - ALSA: usb-audio: do not try to get Benchmark DAC1 sample
    rate (boo#934755).

  - ALSA: usb-audio: do not try to get Outlaw RR2150 sample
    rate (boo#934755).

  - ALSA: usb-audio: fix missing input volume controls in
    MAYA44 USB(+) (boo#934755).

  - Automatically Provide/Obsolete all subpackages of old
    flavors (bnc#925567)

  - Fix kABI for ak411x structs (boo#934755).

  - Fix kABI for snd_emu10k1 struct (boo#934755).

  - HID: add ALWAYS_POLL quirk for a Logitech 0xc007
    (bnc#929624).

  - HID: add HP OEM mouse to quirk ALWAYS_POLL (bnc#929624).

  - HID: add quirk for PIXART OEM mouse used by HP
    (bnc#929624).

  - HID: usbhid: add always-poll quirk (bnc#929624).

  - HID: usbhid: add another mouse that needs
    QUIRK_ALWAYS_POLL (bnc#929624).

  - HID: usbhid: enable always-poll quirk for Elan
    Touchscreen (bnc#929624).

  - HID: usbhid: enable always-poll quirk for Elan
    Touchscreen 009b (bnc#929624).

  - HID: usbhid: enable always-poll quirk for Elan
    Touchscreen 0103 (bnc#929624).

  - HID: usbhid: enable always-poll quirk for Elan
    Touchscreen 016f (bnc#929624).

  - HID: usbhid: fix PIXART optical mouse (bnc#929624).

  - HID: usbhid: more mice with ALWAYS_POLL (bnc#929624).

  - HID: usbhid: yet another mouse with ALWAYS_POLL
    (bnc#929624).

  - HID: yet another buggy ELAN touchscreen (bnc#929624).

  - Input: synaptics - handle spurious release of trackstick
    buttons (bnc#928693).

  - Input: synaptics - re-route tracksticks buttons on the
    Lenovo 2015 series (bnc#928693).

  - Input: synaptics - remove TOPBUTTONPAD property for
    Lenovos 2015 (bnc#928693).

  - Input: synaptics - retrieve the extended capabilities in
    query $10 (bnc#928693).

  - NFSv4: When returning a delegation, do not reclaim an
    incompatible open mode (bnc#934202).

  - Refresh patches.xen/xen-blkfront-indirect (bsc#922235).

  - Update config files: extend CONFIG_DPM_WATCHDOG_TIMEOUT
    to 60 (bnc#934397)

  - arm64: mm: Remove hack in mmap randomized layout Fix
    commit id and mainlined information

  - bnx2x: Fix kdump when iommu=on (bug#921769).

  - client MUST ignore EncryptionKeyLength if
    CAP_EXTENDED_SECURITY is set (bnc#932348).

  - config/armv7hl: Disable AMD_XGBE_PHY The AMD XGBE
    ethernet chip is only used on ARM64 systems.

  - config: disable XGBE on non-ARM hardware It is
    documented as being present only on AMD SoCs.

  - cpufreq: fix a NULL pointer dereference in
    __cpufreq_governor() (bsc#924664).

  - drm/i915/bdw: PCI IDs ending in 0xb are ULT
    (boo#935913).

  - drm/i915/chv: Remove Wait for a previous gfx force-off
    (boo#935913).

  - drm/i915/dp: only use training pattern 3 on platforms
    that support it (boo#935913).

  - drm/i915/dp: there is no audio on port A (boo#935913).

  - drm/i915/hsw: Fix workaround for server AUX channel
    clock divisor (boo#935913).

  - drm/i915/vlv: remove wait for previous GFX clk disable
    request (boo#935913).

  - drm/i915/vlv: save/restore the power context base reg
    (boo#935913).

  - drm/i915: Add missing MacBook Pro models with dual
    channel LVDS (boo#935913).

  - drm/i915: BDW Fix Halo PCI IDs marked as ULT
    (boo#935913).

  - drm/i915: Ban Haswell from using RCS flips (boo#935913).

  - drm/i915: Check obj->vma_list under the struct_mutex
    (boo#935913).

  - drm/i915: Correct the IOSF Dev_FN field for IOSF
    transfers (boo#935913).

  - drm/i915: Dell Chromebook 11 has PWM backlight
    (boo#935913).

  - drm/i915: Disable caches for Global GTT (boo#935913).

  - drm/i915: Do a dummy DPCD read before the actual read
    (bnc#907714).

  - drm/i915: Do not complain about stolen conflicts on gen3
    (boo#935913).

  - drm/i915: Do not leak pages when freeing userptr objects
    (boo#935913).

  - drm/i915: Dont enable CS_PARSER_ERROR interrupts at all
    (boo#935913).

  - drm/i915: Evict CS TLBs between batches (boo#935913).

  - drm/i915: Fix DDC probe for passive adapters
    (boo#935913).

  - drm/i915: Fix and clean BDW PCH identification
    (boo#935913).

  - drm/i915: Force the CS stall for invalidate flushes
    (boo#935913).

  - drm/i915: Handle failure to kick out a conflicting fb
    driver (boo#935913).

  - drm/i915: Ignore SURFLIVE and flip counter when the GPU
    gets reset (boo#935913).

  - drm/i915: Ignore VBT backlight check on Macbook 2, 1
    (boo#935913).

  - drm/i915: Invalidate media caches on gen7 (boo#935913).

  - drm/i915: Kick fbdev before vgacon (boo#935913).

  - drm/i915: Only fence tiled region of object
    (boo#935913).

  - drm/i915: Only warn the first time we attempt to mmio
    whilst suspended (boo#935913).

  - drm/i915: Unlock panel even when LVDS is disabled
    (boo#935913).

  - drm/i915: Use IS_HSW_ULT() in a HSW specific code path
    (boo#935913).

  - drm/i915: cope with large i2c transfers (boo#935913).

  - drm/i915: do not warn if backlight unexpectedly enabled
    (boo#935913).

  - drm/i915: drop WaSetupGtModeTdRowDispatch:snb
    (boo#935913).

  - drm/i915: save/restore GMBUS freq across suspend/resume
    on gen4 (boo#935913).

  - drm/i915: vlv: fix IRQ masking when uninstalling
    interrupts (boo#935913).

  - drm/i915: vlv: fix save/restore of GFX_MAX_REQ_COUNT reg
    (boo#935913).

  - drm/radeon: retry dcpd fetch (bnc#931580).

  - ftrace/x86/xen: use kernel identity mapping only when
    really needed (bsc#873195, bsc#886272, bsc#903727,
    bsc#927725)

  - guards: Add support for an external filelist in --check
    mode This will allow us to run --check without a
    kernel-source.git work tree.

  - guards: Include the file name also in the 'Not found'
    error

  - guards: Simplify help text

  - hyperv: Add processing of MTU reduced by the host
    (bnc#919596).

  - ideapad_laptop: Lenovo G50-30 fix rfkill reports
    wireless blocked (boo#939394).

  - ipv6: do not delete previously existing ECMP routes if
    add fails (bsc#930399).

  - ipv6: fix ECMP route replacement (bsc#930399).

  - ipv6: replacing a rt6_info needs to purge possible
    propagated rt6_infos too (bsc#930399).

  - kABI: protect linux/slab.h include in of/address.

  - kabi/severities: ignore already-broken but acceptable
    kABI changes - SYSTEM_TRUSTED_KEYRING=n change removed
    system_trusted_keyring - Commits 3688875f852 and
    ea5ed8c70e9 changed iov_iter_get_pages prototype - KVM
    changes are intermodule dependencies

  - kabi: Fix CRC for dma_get_required_mask.

  - kabi: add kABI reference files

  - libata: Blacklist queued TRIM on Samsung SSD 850 Pro
    (bsc#926156).

  - libata: Blacklist queued TRIM on all Samsung 800-series
    (bnc#930599).

  - net: ppp: Do not call bpf_prog_create() in ppp_lock
    (bnc#930488).

  - rpm/kernel-obs-qa.spec.in: Do not fail if the kernel
    versions do not match

  - rt2x00: do not align payload on modern H/W (bnc#932844).

  - rtlwifi: rtl8192cu: Fix kernel deadlock (bnc#927786).

  - thermal: step_wise: Revert optimization (boo#925961).

  - tty: Fix pty master poll() after slave closes v2
    (bsc#937138). arm64: mm: Remove hack in mmap randomize
    layout (bsc#937033)

  - udf: Remove repeated loads blocksize (bsc#933907).

  - usb: core: Fix USB 3.0 devices lost in NOTATTACHED state
    after a hub port reset (bnc#937226).

  - x86, apic: Handle a bad TSC more gracefully
    (boo#935530).

  - x86/PCI: Use host bridge _CRS info on Foxconn
    K8M890-8237A (bnc#907092).

  - x86/PCI: Use host bridge _CRS info on systems with >32
    bit addressing (bnc#907092).

  - x86/microcode/amd: Do not overwrite final patch levels
    (bsc#913996).

  - x86/microcode/amd: Extract current patch level read to a
    function (bsc#913996).

  - x86/mm: Improve AMD Bulldozer ASLR workaround
    (bsc#937032).

  - xenbus: add proper handling of XS_ERROR from Xenbus for
    transactions.

  - xhci: Calculate old endpoints correctly on device reset
    (bnc#938976)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=932348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=932844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939394"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen-debuginfo");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-0.8-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-debugsource-0.8-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-0.8_k3.16.7_24-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-debuginfo-0.8_k3.16.7_24-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-0.8_k3.16.7_24-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-debuginfo-0.8_k3.16.7_24-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-0.8_k3.16.7_24-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-debuginfo-0.8_k3.16.7_24-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-0.8_k3.16.7_24-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-debuginfo-0.8_k3.16.7_24-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-2.639-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debuginfo-2.639-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debugsource-2.639-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-2.639_k3.16.7_24-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-debuginfo-2.639_k3.16.7_24-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-2.639_k3.16.7_24-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.16.7_24-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-2.639_k3.16.7_24-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-debuginfo-2.639_k3.16.7_24-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-2.639_k3.16.7_24-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-debuginfo-2.639_k3.16.7_24-14.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-7.0.8-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debuginfo-7.0.8-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debugsource-7.0.8-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-devel-7.0.8-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-7.0.8-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-debuginfo-7.0.8-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-7.0.8-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-debuginfo-7.0.8-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-7.0.8_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-debuginfo-7.0.8_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-7.0.8_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-debuginfo-7.0.8_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-7.0.8_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-debuginfo-7.0.8_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-7.0.8_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-debuginfo-7.0.8_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-debugsource-1.28-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-1.28_k3.16.7_24-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.16.7_24-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-1.28_k3.16.7_24-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.16.7_24-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-1.28_k3.16.7_24-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.16.7_24-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-1.28_k3.16.7_24-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.16.7_24-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-6.23-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debuginfo-6.23-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debugsource-6.23-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-devel-6.23-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-6.23_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-debuginfo-6.23_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-6.23_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-debuginfo-6.23_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-6.23_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-debuginfo-6.23_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-6.23_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-debuginfo-6.23_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-macros-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-3.16.7-24.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-debugsource-3.16.7-24.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-xen-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-vanilla-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-syms-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-6.23-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-debuginfo-6.23-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-0.44-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debuginfo-0.44-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debugsource-0.44-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-0.44_k3.16.7_24-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.16.7_24-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-0.44_k3.16.7_24-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.16.7_24-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-0.44_k3.16.7_24-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.16.7_24-260.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-debugsource-20140629-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-20140629_k3.16.7_24-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-debuginfo-20140629_k3.16.7_24-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-20140629_k3.16.7_24-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-debuginfo-20140629_k3.16.7_24-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-20140629_k3.16.7_24-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-debuginfo-20140629_k3.16.7_24-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-20140629_k3.16.7_24-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-debuginfo-20140629_k3.16.7_24-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-debugsource-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-devel-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-debuginfo-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-debuginfo-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-2.6-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debuginfo-2.6-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debugsource-2.6-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-2.6_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-debuginfo-2.6_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-2.6_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-debuginfo-2.6_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-2.6_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-debuginfo-2.6_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-2.6_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-debuginfo-2.6_k3.16.7_24-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-devel-3.16.7-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-doc-html-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-4.4.2_06_k3.16.7_24-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.2_06_k3.16.7_24-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-4.4.2_06_k3.16.7_24-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-debuginfo-4.4.2_06_k3.16.7_24-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-32bit-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-4.4.2_06-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.2_06-25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bbswitch / bbswitch-debugsource / bbswitch-kmp-default / etc");
}
