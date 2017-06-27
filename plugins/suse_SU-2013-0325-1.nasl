#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0325-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83575);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2012-1586", "CVE-2013-0213", "CVE-2013-0214");
  script_bugtraq_id(52742, 53246, 57631);

  script_name(english:"SUSE SLED10 / SLES10 Security Update : Samba (SUSE-SU-2013:0325-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Samba Web Administration Tool (SWAT) in Samba versions 3.0.x to
4.0.1 was affected by a cross-site request forgery (CVE-2013-0214) and
a click-jacking attack (CVE-2013-0213). This has been fixed.

Additionally a bug in mount.cifs has been fixed which could have lead
to file disclosure (CVE-2012-1586).

Also a uninitialized memory read bug in talloc_free() has been fixed.
(bnc#764577).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=1d50d01aa74b22f0c8645692c12273df
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?103a9177"
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
    value:"https://bugzilla.novell.com/754443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/764577"
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
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130325-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45298ec3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected Samba packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cifs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmsrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmsrpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-vscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/22");
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
if (! ereg(pattern:"^(SLED10|SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"cifs-mount-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"ldapsmb-1.34b-25.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"libsmbclient-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"libsmbclient-devel-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"samba-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"samba-client-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"samba-krb-printing-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"samba-vscan-0.3.6b-43.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"samba-winbind-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"samba-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"cifs-mount-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"ldapsmb-1.34b-25.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"libsmbclient-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"libsmbclient-devel-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"samba-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"samba-client-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"samba-krb-printing-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"samba-vscan-0.3.6b-43.13.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"samba-winbind-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"samba-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"libsmbclient-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"samba-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"samba-client-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"samba-winbind-32bit-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"cifs-mount-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"ldapsmb-1.34b-25.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"libmsrpc-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"libmsrpc-devel-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"libsmbclient-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"libsmbclient-devel-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-client-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-krb-printing-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-python-3.0.36-0.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-vscan-0.3.6b-43.13.24.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-winbind-3.0.36-0.13.24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Samba");
}
