#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-124.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88545);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2014-2568", "CVE-2014-8133", "CVE-2014-8989", "CVE-2014-9090", "CVE-2014-9419", "CVE-2014-9529", "CVE-2014-9683", "CVE-2014-9715", "CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-0272", "CVE-2015-0777", "CVE-2015-1420", "CVE-2015-1421", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2666", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-2925", "CVE-2015-3212", "CVE-2015-3339", "CVE-2015-3636", "CVE-2015-4001", "CVE-2015-4002", "CVE-2015-4003", "CVE-2015-4004", "CVE-2015-4036", "CVE-2015-4167", "CVE-2015-4692", "CVE-2015-4700", "CVE-2015-5157", "CVE-2015-5283", "CVE-2015-5307", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5707", "CVE-2015-6937", "CVE-2015-7550", "CVE-2015-7799", "CVE-2015-7833", "CVE-2015-7872", "CVE-2015-7885", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575", "CVE-2015-8767", "CVE-2016-0728");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-124)");
  script_summary(english:"Check for the openSUSE-2016-124 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.1 kernel was updated to receive various security and
bugfixes.

Following security bugs were fixed :

  - CVE-2016-0728: A reference leak in keyring handling with
    join_session_keyring() could lead to local attackers
    gain root privileges. (bsc#962075).

  - CVE-2015-7550: A local user could have triggered a race
    between read and revoke in keyctl (bnc#958951).

  - CVE-2015-8569: The (1) pptp_bind and (2) pptp_connect
    functions in drivers/net/ppp/pptp.c in the Linux kernel
    did not verify an address length, which allowed local
    users to obtain sensitive information from kernel memory
    and bypass the KASLR protection mechanism via a crafted
    application (bnc#959190).

  - CVE-2015-8543: The networking implementation in the
    Linux kernel did not validate protocol identifiers for
    certain protocol families, which allowed local users to
    cause a denial of service (NULL function pointer
    dereference and system crash) or possibly gain
    privileges by leveraging CLONE_NEWUSER support to
    execute a crafted SOCK_RAW application (bnc#958886).

  - CVE-2014-8989: The Linux kernel did not properly
    restrict dropping of supplemental group memberships in
    certain namespace scenarios, which allowed local users
    to bypass intended file permissions by leveraging a
    POSIX ACL containing an entry for the group category
    that is more restrictive than the entry for the other
    category, aka a 'negative groups' issue, related to
    kernel/groups.c, kernel/uid16.c, and
    kernel/user_namespace.c (bnc#906545).

  - CVE-2015-5157: arch/x86/entry/entry_64.S in the Linux
    kernel on the x86_64 platform mishandles IRET faults in
    processing NMIs that occurred during userspace
    execution, which might allow local users to gain
    privileges by triggering an NMI (bnc#937969).

  - CVE-2015-7799: The slhc_init function in
    drivers/net/slip/slhc.c in the Linux kernel through
    4.2.3 did not ensure that certain slot numbers are
    valid, which allowed local users to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted PPPIOCSMAXCID ioctl call (bnc#949936).

  - CVE-2015-8104: The KVM subsystem in the Linux kernel
    through 4.2.6, and Xen 4.3.x through 4.6.x, allowed
    guest OS users to cause a denial of service (host OS
    panic or hang) by triggering many #DB (aka Debug)
    exceptions, related to svm.c (bnc#954404).

  - CVE-2015-5307: The KVM subsystem in the Linux kernel
    through 4.2.6, and Xen 4.3.x through 4.6.x, allowed
    guest OS users to cause a denial of service (host OS
    panic or hang) by triggering many #AC (aka Alignment
    Check) exceptions, related to svm.c and vmx.c
    (bnc#953527).

  - CVE-2014-9529: Race condition in the key_gc_unused_keys
    function in security/keys/gc.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption or panic) or possibly have unspecified other
    impact via keyctl commands that trigger access to a key
    structure member during garbage collection of a key
    (bnc#912202).

  - CVE-2015-7990: Race condition in the rds_sendmsg
    function in net/rds/sendmsg.c in the Linux kernel
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) or possibly have
    unspecified other impact by using a socket that was not
    properly bound. NOTE: this vulnerability exists because
    of an incomplete fix for CVE-2015-6937 (bnc#952384
    953052).

  - CVE-2015-6937: The __rds_conn_create function in
    net/rds/connection.c in the Linux kernel allowed local
    users to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact by using a socket that was not
    properly bound (bnc#945825).

  - CVE-2015-7885: The dgnc_mgmt_ioctl function in
    drivers/staging/dgnc/dgnc_mgmt.c in the Linux kernel
    through 4.3.3 did not initialize a certain structure
    member, which allowed local users to obtain sensitive
    information from kernel memory via a crafted application
    (bnc#951627).

  - CVE-2015-8215: net/ipv6/addrconf.c in the IPv6 stack in
    the Linux kernel did not validate attempted changes to
    the MTU value, which allowed context-dependent attackers
    to cause a denial of service (packet loss) via a value
    that is (1) smaller than the minimum compliant value or
    (2) larger than the MTU of an interface, as demonstrated
    by a Router Advertisement (RA) message that is not
    validated by a daemon, a different vulnerability than
    CVE-2015-0272. NOTE: the scope of CVE-2015-0272 is
    limited to the NetworkManager product (bnc#955354).

  - CVE-2015-8767: A case can occur when sctp_accept() is
    called by the user during a heartbeat timeout event
    after the 4-way handshake. Since sctp_assoc_migrate()
    changes both assoc->base.sk and assoc->ep, the
    bh_sock_lock in sctp_generate_heartbeat_event() will be
    taken with the listening socket but released with the
    new association socket. The result is a deadlock on any
    future attempts to take the listening socket lock.
    (bsc#961509)

  - CVE-2015-8575: Validate socket address length in
    sco_sock_bind() to prevent information leak
    (bsc#959399).

  - CVE-2015-8551, CVE-2015-8552: xen/pciback: For
    XEN_PCI_OP_disable_msi[|x] only disable if device has
    MSI(X) enabled (bsc#957990).

  - CVE-2015-8550: Compiler optimizations in the XEN PV
    backend drivers could have lead to double fetch
    vulnerabilities, causing denial of service or arbitrary
    code execution (depending on the configuration)
    (bsc#957988).

The following non-security bugs were fixed :

  - ALSA: hda - Disable 64bit address for Creative HDA
    controllers (bnc#814440).

  - ALSA: hda - Fix noise problems on Thinkpad T440s
    (boo#958504).

  - Input: aiptek - fix crash on detecting device without
    endpoints (bnc#956708).

  - KEYS: Make /proc/keys unconditional if CONFIG_KEYS=y
    (boo#956934).

  - KVM: x86: update masterclock values on TSC writes
    (bsc#961739).

  - NFS: Fix a NULL pointer dereference of migration
    recovery ops for v4.2 client (bsc#960839).

  - apparmor: allow SYS_CAP_RESOURCE to be sufficient to
    prlimit another task (bsc#921949).

  - blktap: also call blkif_disconnect() when frontend
    switched to closed (bsc#952976).

  - blktap: refine mm tracking (bsc#952976).

  - cdrom: Random writing support for BD-RE media
    (bnc#959568).

  - genksyms: Handle string literals with spaces in
    reference files (bsc#958510).

  - ipv4: Do not increase PMTU with Datagram Too Big message
    (bsc#955224).

  - ipv6: distinguish frag queues by device for multicast
    and link-local packets (bsc#955422).

  - ipv6: fix tunnel error handling (bsc#952579).

  - route: Use ipv4_mtu instead of raw rt_pmtu (bsc#955224).

  - uas: Add response iu handling (bnc#954138).

  - usbvision fix overflow of interfaces array (bnc#950998).

  - x86/evtchn: make use of PHYSDEVOP_map_pirq.

  - xen/pciback: Do not allow MSI-X ops if
    PCI_COMMAND_MEMORY is not set (bsc#957990 XSA-157)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=814440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=851610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=869564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=873385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=918333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=932348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933934"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=940338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962075"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-xen-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-pae-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-xend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-xend-tools-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/03");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"cloop-2.639-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debuginfo-2.639-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debugsource-2.639-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-2.639_k3.11.10_34-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-debuginfo-2.639_k3.11.10_34-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-2.639_k3.11.10_34-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.11.10_34-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-2.639_k3.11.10_34-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-debuginfo-2.639_k3.11.10_34-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-2.639_k3.11.10_34-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-debuginfo-2.639_k3.11.10_34-11.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-7.0.2-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debuginfo-7.0.2-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debugsource-7.0.2-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-devel-7.0.2-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-7.0.2-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-debuginfo-7.0.2-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-7.0.2-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-debuginfo-7.0.2-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-7.0.2_k3.11.10_34-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-debuginfo-7.0.2_k3.11.10_34-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-7.0.2_k3.11.10_34-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-debuginfo-7.0.2_k3.11.10_34-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-7.0.2_k3.11.10_34-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-debuginfo-7.0.2_k3.11.10_34-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-7.0.2_k3.11.10_34-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-debuginfo-7.0.2_k3.11.10_34-2.23.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-debugsource-1.28-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-1.28_k3.11.10_34-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.11.10_34-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-1.28_k3.11.10_34-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.11.10_34-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-1.28_k3.11.10_34-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.11.10_34-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-1.28_k3.11.10_34-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.11.10_34-16.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-6.21.1-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debuginfo-6.21.1-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debugsource-6.21.1-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-devel-6.21.1-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-6.21.1_k3.11.10_34-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-debuginfo-6.21.1_k3.11.10_34-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-6.21.1_k3.11.10_34-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-debuginfo-6.21.1_k3.11.10_34-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-6.21.1_k3.11.10_34-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-debuginfo-6.21.1_k3.11.10_34-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-6.21.1_k3.11.10_34-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-debuginfo-6.21.1_k3.11.10_34-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-1.4.20.3-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debuginfo-1.4.20.3-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debugsource-1.4.20.3-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-1.4.20.3_k3.11.10_34-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-debuginfo-1.4.20.3_k3.11.10_34-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-1.4.20.3_k3.11.10_34-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-debuginfo-1.4.20.3_k3.11.10_34-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-1.4.20.3_k3.11.10_34-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-debuginfo-1.4.20.3_k3.11.10_34-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-1.4.20.3_k3.11.10_34-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-debuginfo-1.4.20.3_k3.11.10_34-13.23.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-devel-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-vanilla-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-syms-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-6.21.1-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-debuginfo-6.21.1-2.27.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-1.58-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debuginfo-1.58-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debugsource-1.58-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-1.58_k3.11.10_34-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-debuginfo-1.58_k3.11.10_34-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-1.58_k3.11.10_34-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-debuginfo-1.58_k3.11.10_34-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-1.58_k3.11.10_34-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-debuginfo-1.58_k3.11.10_34-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-0.44-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debuginfo-0.44-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debugsource-0.44-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-0.44_k3.11.10_34-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.11.10_34-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-0.44_k3.11.10_34-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.11.10_34-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-0.44_k3.11.10_34-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.11.10_34-258.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-debuginfo-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-debugsource-20130607-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-20130607_k3.11.10_34-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-debuginfo-20130607_k3.11.10_34-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-20130607_k3.11.10_34-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-debuginfo-20130607_k3.11.10_34-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-20130607_k3.11.10_34-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-debuginfo-20130607_k3.11.10_34-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-20130607_k3.11.10_34-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-debuginfo-20130607_k3.11.10_34-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debuginfo-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debugsource-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-devel-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-debuginfo-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-debuginfo-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-debuginfo-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.2.36_k3.11.10_34-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-source-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-debuginfo-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-debuginfo-4.2.36-2.56.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-debugsource-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-devel-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-4.3.4_10_k3.11.10_34-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-debuginfo-4.3.4_10_k3.11.10_34-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-4.3.4_10_k3.11.10_34-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-debuginfo-4.3.4_10_k3.11.10_34-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-4.3.4_10_k3.11.10_34-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-debuginfo-4.3.4_10_k3.11.10_34-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-debuginfo-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-debuginfo-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-2.3-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debuginfo-2.3-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debugsource-2.3-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-2.3_k3.11.10_34-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-debuginfo-2.3_k3.11.10_34-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-2.3_k3.11.10_34-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-debuginfo-2.3_k3.11.10_34-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-2.3_k3.11.10_34-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-debuginfo-2.3_k3.11.10_34-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-2.3_k3.11.10_34-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-debuginfo-2.3_k3.11.10_34-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debuginfo-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debugsource-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.11.10-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.11.10-34.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-doc-html-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-32bit-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-4.3.4_10-57.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-debuginfo-4.3.4_10-57.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cloop / cloop-debuginfo / cloop-debugsource / cloop-kmp-default / etc");
}
