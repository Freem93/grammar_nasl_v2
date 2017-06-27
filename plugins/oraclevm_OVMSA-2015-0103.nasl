#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0103.
#

include("compat.inc");

if (description)
{
  script_id(85144);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/05/05 13:31:48 $");

  script_cve_id("CVE-2014-9680");
  script_bugtraq_id(72649);
  script_osvdb_id(118397);

  script_name(english:"OracleVM 3.3 : sudo (OVMSA-2015-0103)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - RHEL-6.7 erratum

  - modified the authlogicfix patch to fix #1144448

  - fixed a bug in the ldapusermatchfix patch Resolves:
    rhbz#1144448 Resolves: rhbz#1142122

  - RHEL-6.7 erratum

  - fixed the mantypos-ldap.patch Resolves: rhbz#1138267

  - RHEL-6.7 erratum

  - added patch for (CVE-2014-9680)

  - added BuildRequires for tzdata Resolves: rhbz#1200253

  - RHEL-6.7 erratum

  - added zlib-devel build required to enable zlib
    compression support

  - fixed two typos in the sudoers.ldap man page

  - fixed a hang when duplicate nss entries are specified in
    nsswitch.conf

  - SSSD: implemented sorting of the result entries
    according to the sudoOrder attribute

  - LDAP: fixed logic handling the computation of the 'user
    matched' flag

  - fixed restoring of the SIGPIPE signal in the tgetpass
    function

  - fixed listpw, verifypw + authenticate option logic in
    LDAP/SSSD Resolves: rhbz#1106433 Resolves: rhbz#1138267
    Resolves: rhbz#1147498 Resolves: rhbz#1138581 Resolves:
    rhbz#1142122 Resolves: rhbz#1094548 Resolves:
    rhbz#1144448

  - RHEL-6.6 erratum

  - SSSD: dropped the ipahostnameshort patch, as it is not
    needed. rhbz#1033703 is a configuration issue. Related:
    rhbz#1033703

  - RHEL-6.6 erratum

  - SSSD: fixed netgroup filter patch

  - SSSD: dropped serparate patch for #1006463, the fix is
    now part of the netgroup filter patch Resolves:
    rhbz#1006463 Resolves: rhbz#1083064

  - RHEL-6.6 erratum

  - don't retry authentication when ctrl-c pressed

  - fix double-quote processing in Defaults options

  - fix sesh login shell argv[0]

  - handle the '(none)' hostname correctly

  - SSSD: fix ipa_hostname handling

  - SSSD: fix sudoUser netgroup specification filtering

  - SSSD: list correct user when -U <user> -l specified

  - SSSD: show rule names on long listing (-ll) Resolves:
    rhbz#1065415 Resolves: rhbz#1078338 Resolves:
    rhbz#1052940 Resolves: rhbz#1083064 Resolves:
    rhbz#1033703 Resolves: rhbz#1006447 Resolves:
    rhbz#1006463 Resolves: rhbz#1070952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-July/000351.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");
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
if (rpm_check(release:"OVS3.3", reference:"sudo-1.8.6p3-19.el6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
