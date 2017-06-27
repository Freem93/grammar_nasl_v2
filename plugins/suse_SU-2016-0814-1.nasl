#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0814-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90063);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-7560");
  script_osvdb_id(135621);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : samba (SUSE-SU-2016:0814-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for samba fixes the following issues :

  - CVE-2015-7560: Getting and setting Windows ACLs on
    symlinks can change permissions on link target.
    (bso#11648 bsc#968222)

Also the following bugs were fixed :

  - Add quotes around path of update-apparmor-samba-profile;
    (bsc#962177).

  - Prevent access denied if the share path is '/';
    (bso#11647); (bsc#960249).

  - Ensure samlogon fallback requests are rerouted after
    kerberos failure; (bsc#953382).

  - samba: winbind crash ->
    netlogon_creds_client_authenticator; (bsc#953972).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7560.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160814-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7e582cb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-477=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-477=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-477=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libregistry0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libregistry0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-raw0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-raw0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpdb0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpdb0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libregistry0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libregistry0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debugsource-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpdb0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpdb0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libdcerpc0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgensec0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgensec0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgensec0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-standard0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-standard0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr-standard0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libndr0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libnetapi0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libnetapi0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libnetapi0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpdb0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpdb0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpdb0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpdb0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libregistry0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libregistry0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-util0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-util0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamba-util0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamdb0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamdb0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsamdb0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient-raw0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbclient0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbconf0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbconf0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbconf0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbldap0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbldap0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmbldap0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtevent-util0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtevent-util0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtevent-util0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwbclient0-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwbclient0-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwbclient0-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-client-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-client-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-client-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-debugsource-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-libs-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-libs-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-libs-debuginfo-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-winbind-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-winbind-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.1.12-18.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"samba-winbind-debuginfo-4.1.12-18.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
