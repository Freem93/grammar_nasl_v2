#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0723-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83623);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2012-6150", "CVE-2013-0213", "CVE-2013-0214", "CVE-2013-4124", "CVE-2013-4408", "CVE-2013-4496");
  script_bugtraq_id(57631, 61597, 64101, 64191, 66336);

  script_name(english:"SUSE SLES11 Security Update : Samba (SUSE-SU-2014:0723-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a LTSS roll-up update for the Samba Server suite fixing
multiple security issues and bugs.

Security issues fixed :

  - CVE-2013-4496: Password lockout was not enforced for
    SAMR password changes, leading to brute force
    possibility.

  - CVE-2013-4408: DCE-RPC fragment length field is
    incorrectly checked.

  - CVE-2013-4124: Samba was affected by a denial of service
    attack on authenticated or guest connections.

  - CVE-2013-0214: The SWAT webadministration was affected
    by a cross site scripting attack (XSS).

  - CVE-2013-0213: The SWAT webadministration could possibly
    be used in clickjacking attacks.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=20647ef4a682db1b2ce9c1aec3368f57
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52b7a1db"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6150.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4124.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4408.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4496.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/783384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/799641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/800982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/829969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/844720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853347"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140723-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32d2ffa8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-cifs-mount-9117

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cifs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^1$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"libtalloc1-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"libtdb1-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"samba-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"libsmbclient0-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"libtalloc1-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"libtdb1-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"libwbclient0-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"samba-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"samba-client-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", cpu:"s390x", reference:"samba-winbind-32bit-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"cifs-mount-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"ldapsmb-1.34b-11.28.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"libsmbclient0-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"libtalloc1-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"libtdb1-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"libwbclient0-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"samba-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"samba-client-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"samba-krb-printing-3.4.3-1.52.3")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"samba-winbind-3.4.3-1.52.3")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Samba");
}
