#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0539-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83620);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2014-0076");
  script_bugtraq_id(66363);
  script_osvdb_id(104810);

  script_name(english:"SUSE SLES10 Security Update : OpenSSL (SUSE-SU-2014:0539-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL has been updated to fix an attack on ECDSA Nonces.

Using the FLUSH+RELOAD Cache Side-channel Attack the Nonces could be
recovered. (CVE-2014-0076)

The update also enables use of SHA-2 family certificate verification
of X.509 certificates used in todays SSL certificate infrastructure.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=5e45bbc40560ab190992f4af60dbbccc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc0e8a3c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/866916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/869945"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140539-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b59e93c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenSSL packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"openssl-32bit-0.9.8a-18.45.75.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"openssl-devel-32bit-0.9.8a-18.45.75.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"openssl-32bit-0.9.8a-18.45.75.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"openssl-devel-32bit-0.9.8a-18.45.75.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"openssl-0.9.8a-18.45.75.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"openssl-devel-0.9.8a-18.45.75.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"openssl-doc-0.9.8a-18.45.75.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenSSL");
}
