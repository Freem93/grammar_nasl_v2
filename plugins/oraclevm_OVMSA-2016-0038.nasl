#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0038.
#

include("compat.inc");

if (description)
{
  script_id(90076);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2010-5107", "CVE-2014-2532", "CVE-2014-2653", "CVE-2015-5600", "CVE-2016-3115");
  script_bugtraq_id(58162, 66355, 66459);
  script_osvdb_id(90007, 104578, 105011, 124938, 135714);

  script_name(english:"OracleVM 3.3 / 3.4 : openssh (OVMSA-2016-0038)");
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

  - CVE-2015-5600: MaxAuthTries limit bypass via duplicates
    in KbdInteractiveDevices (#1245969)

  - CVE-2016-3115: missing sanitisation of input for X11
    forwarding (#1317816)

  - SSH2_MSG_DISCONNECT for user initiated disconnect follow
    RFC 4253 (#1222500)

  - Add missing dot in ssh manual page (#1197763)

  - Fix minor problems found by covscan/gcc (#1196063)

  - Add missing options in man ssh (#1197763)

  - Add KbdInteractiveAuthentication documentation to man
    sshd_config (#1109251)

  - Correct freeing newkeys structure when privileged
    monitor exits (#1208584)

  - Fix problems with failing persistent connections
    (#1131585)

  - Fix memory leaks in auditing patch (#1208584)

  - Better approach to logging sftp commands in chroot

  - Make sshd -T write all config options and add missing
    Cipher, MAC to man (#1109251)

  - Add missing ControlPersist option to man ssh (#1197763)

  - Add sftp option to force mode of created files
    (#1191055)

  - Do not load RSA1 keys in FIPS mode (#1197072)

  - Add missing support for ECDSA in ssh-keyscan (#1196331)

  - Fix coverity/gcc issues (#1196063)

  - Backport wildcard functionality for PermitOpen in
    sshd_config file (#1159055)

  - Ability to specify an arbitrary LDAP filter in ldap.conf
    (#1119506)

  - Fix ControlPersist option with ProxyCommand (#1160487)

  - Backport fix of ssh-keygen with error : gethostname:
    File name too long (#1161454)

  - Backport show remote address instead of UNKNOWN after
    timeout at password prompt (#1161449)

  - Fix printing of extensions in v01 certificates
    (#1093869)

  - Fix confusing audit trail for unsuccessful logins
    (#1127312)

  - Don't close fds for internal sftp sessions (#1085710)

  - Fix config parsing quotes (backport) (#1134938)

  - Enable logging in chroot into separate file (#1172224)

  - Fix auditing when using combination of ForcedCommand and
    PTY (#1131585)

  - Fix ssh-copy-id on non-sh remote shells (#1135521)

  - ignore SIGXFSZ in postauth monitor child (#1133906)

  - don't try to generate DSA keys in the init script in
    FIPS mode (#1118735)

  - ignore SIGPIPE in ssh-keyscan (#1108836)

  - ssh-add: fix fatal exit when removing card (#1042519)

  - fix race in backported ControlPersist patch (#953088)

  - skip requesting smartcard PIN when removing keys from
    agent (#1042519)

  - add possibility to autocreate only RSA key into
    initscript (#1111568)

  - fix several issues reported by coverity

  - x11 forwarding - be less restrictive when can't bind to
    one of available addresses (#1027197)

  - better fork error detection in audit patch (#1028643)

  - fix openssh-5.3p1-x11.patch for non-linux platforms
    (#1100913)

  - prevent a server from skipping SSHFP lookup (#1081338)
    (CVE-2014-2653)

  - ignore environment variables with embedded '=' or '\0'
    characters (CVE-2014-2532)

  - backport ControlPersist option (#953088)

  - log when a client requests an interactive session and
    only sftp is allowed (#997377)

  - don't try to load RSA1 host key in FIPS mode (#1009959)

  - restore Linux oom_adj setting when handling SIGHUP to
    maintain behaviour over restart (#1010429)

  - ssh-keygen -V - relative-specified certificate expiry
    time should be relative to current time (#1022459)

  - adjust the key echange DH groups and ssh-keygen
    according to SP800-131A (#993580)

  - log failed integrity test if /etc/system-fips exists
    (#1020803)

  - backport ECDSA and ECDH support (#1028335)

  - use dracut-fips package to determine if a FIPS module is
    installed (#1001565)

  - use dist tag in suffixes for hmac checksum files
    (#1001565)

  - use hmac_suffix for ssh[,d] hmac checksums (#1001565)

  - fix NSS keys support (#1004763)

  - change default value of MaxStartups - CVE-2010-5107 -
    #908707

  - add -fips subpackages that contains the FIPS module
    files (#1001565)

  - don't use SSH_FP_MD5 for fingerprints in FIPS mode
    (#998835)

  - do ssh_gssapi_krb5_storecreds twice - before and after
    pam sesssion (#974096)

  - bump the minimum value of SSH_USE_STRONG_RNG to 14
    according to SP800-131A (#993577)

  - fixed an issue with broken 'ssh -I pkcs11' (#908038)

  - abort non-subsystem sessions to forced internal
    sftp-server (#993509)

  - reverted 'store krb5 credentials after a pam session is
    created (#974096)'

  - Add support for certificate key types for users and
    hosts (#906872)

  - Apply RFC3454 stringprep to banners when possible
    (#955792)

  - fix chroot logging issue (#872169)

  - change the bad key permissions error message (#880575)

  - fix a race condition in ssh-agent (#896561)

  - backport support for PKCS11 from openssh-5.4p1 (#908038)

  - add a KexAlgorithms knob to the client and server
    configuration (#951704)

  - fix parsing logic of ldap.conf file (#954094)

  - Add HMAC-SHA2 algorithm support (#969565)

  - store krb5 credentials after a pam session is created
    (#974096)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-March/000449.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8801e58b"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-March/000443.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11579ee9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssh / openssh-clients / openssh-server
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"openssh-5.3p1-114.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"openssh-clients-5.3p1-114.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"openssh-server-5.3p1-114.el6_7")) flag++;

if (rpm_check(release:"OVS3.4", reference:"openssh-5.3p1-114.el6_7")) flag++;
if (rpm_check(release:"OVS3.4", reference:"openssh-clients-5.3p1-114.el6_7")) flag++;
if (rpm_check(release:"OVS3.4", reference:"openssh-server-5.3p1-114.el6_7")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-clients / openssh-server");
}
