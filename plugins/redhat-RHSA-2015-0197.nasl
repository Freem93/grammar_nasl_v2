#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0197. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85713);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-3509", "CVE-2014-3511");
  script_osvdb_id(109896, 109902);
  script_xref(name:"RHSA", value:"2015:0197");

  script_name(english:"RHEL 6 : rhevm-spice-client (RHSA-2015:0197)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rhevm-spice-client packages that fix two security issues and
several bugs are now available for Red Hat Enterprise Virtualization
Manager 3.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat Enterprise Virtualization Manager provides access to virtual
machines using SPICE. These SPICE client packages provide the SPICE
client and usbclerk service for both Windows 32-bit operating systems
and Windows 64-bit operating systems.

A race condition was found in the way OpenSSL handled ServerHello
messages with an included Supported EC Point Format extension. A
malicious server could possibly use this flaw to cause a
multi-threaded TLS/SSL client using OpenSSL to write into freed
memory, causing the client to crash or execute arbitrary code.
(CVE-2014-3509)

A flaw was found in the way OpenSSL handled fragmented handshake
packets. A man-in-the-middle attacker could use this flaw to force a
TLS/SSL server using OpenSSL to use TLS 1.0, even if both the client
and the server supported newer protocol versions. (CVE-2014-3511)

This update also fixes the following bugs :

* Previously, various clipboard managers, operating on the client or
on the guest, would occasionally lose synchronization, which resulted
in clipboard data loss and the SPICE console freezing. Now, spice-gtk
have been patched, such that clipboard synchronization does not freeze
the SPICE console anymore. (BZ#1083489)

* Prior to this update, when a SPICE console was launched from the Red
Hat Enterprise Virtualization User Portal with the 'Native Client'
invocation method and 'Open in Full Screen' selected, the displays of
the guest virtual machine were not always configured to match the
client displays. After this update, the SPICE console will show a
full-screen guest display for each client monitor. (BZ#1076243)

* A difference in behavior between Linux and Windows clients caused an
extra nul character to be sent when pasting text in a guest machine
from a Windows client. This invisible character was visible in some
Java applications. With this update, the extra nul character is
removed from text strings and no more extraneous character would
appear. (BZ#1090122)

* Previously, If the clipboard is of type image/bmp, and the data is
of 0 size, GTK+ will crash. With this update, the data size is checked
first, and GTK+ no longer crashes when clipboard is of type image/bmp,
and the data is of 0 size. (BZ#1090433)

* Modifier-only key combinations cannot be registered by users as
hotkeys so if a user tries to set a modifier-only key sequence (for
example, 'ctrl+alt') as the hotkey for releasing the cursor, it will
fail, and the user will be able to release the cursor from the window.
With this update, when a modifier-only hotkey is attempted to be
registered, it will fall back to the default cursor-release sequence
(which happens to be 'ctrl+alt'). (BZ#985319)

* Display configuration sometimes used outdated information about the
position of the remote-viewer windows in order to align and configure
the guest displays. Occasionally, this caused the guest displays to
became unexpectedly swapped when a window is resized. With this
update, remote-viewer will always use the current window locations to
align displays, rather than using a possibly outdated cached location
information. (BZ#1018182)

All rhevm-spice-client users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0197.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-spice-client-x64-cab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-spice-client-x64-msi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-spice-client-x86-cab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-spice-client-x86-msi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0197";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_exists(rpm:"rhevm-spice-client-x64-cab-3.5-", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-spice-client-x64-cab-3.5-2.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-spice-client-x64-msi-3.5-", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-spice-client-x64-msi-3.5-2.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-spice-client-x86-cab-3.5-", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-spice-client-x86-cab-3.5-2.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-spice-client-x86-msi-3.5-", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-spice-client-x86-msi-3.5-2.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm-spice-client-x64-cab / rhevm-spice-client-x64-msi / etc");
  }
}
