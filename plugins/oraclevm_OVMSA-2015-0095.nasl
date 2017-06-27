#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0095.
#

include("compat.inc");

if (description)
{
  script_id(85037);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-2152", "CVE-2015-5154");
  script_bugtraq_id(73068);
  script_osvdb_id(119565, 125389);

  script_name(english:"OracleVM 3.3 : xen (OVMSA-2015-0095)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - ide: Clear DRQ after handling all expected accesses This
    is additional hardening against an end_transfer_func
    that fails to clear the DRQ status bit. The bit must be
    unset as soon as the PIO transfer has completed, so it's
    better to do this in a central place instead of
    duplicating the code in all commands (and forgetting it
    in some).

    This is XSA-138 CVE-2015-5154 (CVE-2015-5154)

  - ide/atapi: Fix START STOP UNIT command completion The
    command must be completed on all code paths. START STOP
    UNIT with pwrcnd set should succeed without doing
    anything.

    This is XSA-138 CVE-2015-5154 (CVE-2015-5154)

  - ide: Check array bounds before writing to io_buffer
    (CVE-2015-5154) If the end_transfer_func of a command is
    called because enough data has been read or written for
    the current PIO transfer, and it fails to correctly call
    the command completion functions, the DRQ bit in the
    status register and s->end_transfer_func may remain set.
    This allows the guest to access further bytes in
    s->io_buffer beyond s->data_end, and eventually
    overflowing the io_buffer. One case where this currently
    happens is emulation of the ATAPI command START STOP
    UNIT. This patch fixes the problem by adding explicit
    array bounds checks before accessing the buffer instead
    of relying on end_transfer_func to function correctly.
    Cc :

    This is XSA-138 (CVE-2015-5154)

  - ide: Clear DRQ after handling all expected accesses This
    is additional hardening against an end_transfer_func
    that fails to clear the DRQ status bit. The bit must be
    unset as soon as the PIO transfer has completed, so it's
    better to do this in a central place instead of
    duplicating the code in all commands (and forgetting it
    in some).

    This is XSA-138 (CVE-2015-5154)

  - ide: Check array bounds before writing to io_buffer If
    the end_transfer_func of a command is called because
    enough data has been read or written for the current PIO
    transfer, and it fails to correctly call the command
    completion functions, the DRQ bit in the status register
    and s->end_transfer_func may remain set. This allows the
    guest to access further bytes in s->io_buffer beyond
    s->data_end, and eventually overflowing the io_buffer.
    One case where this currently happens is emulation of
    the ATAPI command START STOP UNIT. This patch fixes the
    problem by adding explicit array bounds checks before
    accessing the buffer instead of relying on
    end_transfer_func to function correctly. Cc :

    This is XSA-138 (CVE-2015-5154)

  - tools: libxl: Explicitly disable graphics backends on
    qemu cmdline By default qemu will try to create some
    sort of backend for the emulated VGA device, either SDL
    or VNC. However when the user specifies sdl=0 and vnc=0
    in their configuration libxl was not explicitly
    disabling either backend, which could lead to one
    unexpectedly running. If either sdl=1 or vnc=1 is
    configured then both before and after this change only
    the backends which are explicitly enabled are
    configured, i.e. this issue only occurs when all
    backends are supposed to have been disabled. This
    affects qemu-xen and qemu-xen-traditional differently.
    If qemu-xen was compiled with SDL support then this
    would result in an SDL window being opened if $DISPLAY
    is valid, or a failure to start the guest if not.
    Passing '-display none' to qemu before any further

    -sdl options disables this default behaviour and ensures
    that SDL is only started if the libxl configuration
    demands it. If qemu-xen was compiled without SDL support
    then qemu would instead start a VNC server listening on
    ::1 (IPv6 localhost) or 127.0.0.1 (IPv4 localhost) with
    IPv6 preferred if available. Explicitly pass '-vnc none'
    when vnc is not enabled in the libxl configuration to
    remove this possibility. qemu-xen-traditional would
    never start a vnc backend unless asked. However by
    default it will start an SDL backend, the way to disable
    this is to pass a -vnc option. In other words passing
    '-vnc none' will disable both vnc and sdl by default.
    sdl can then be reenabled if configured by subsequent
    use of the -sdl option. Tested with both qemu-xen and
    qemu-xen-traditional built with SDL support and: xl cr #
    defaults xl cr sdl=0 vnc=0 xl cr sdl=1 vnc=0 xl cr sdl=0
    vnc=1 xl cr sdl=0 vnc=0 vga='none' xl cr sdl=0 vnc=0
    nographic=1 with both valid and invalid $DISPLAY. This
    is XSA-119 / CVE-2015-2152. (CVE-2015-2152)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-July/000343.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"xen-4.3.0-55.el6.47.39")) flag++;
if (rpm_check(release:"OVS3.3", reference:"xen-tools-4.3.0-55.el6.47.39")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
