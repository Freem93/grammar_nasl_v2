#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1181-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84558);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-4000");
  script_bugtraq_id(74733, 75156, 75157, 75158);
  script_osvdb_id(122331, 123172, 123173, 123174);

  script_name(english:"SUSE SLES10 Security Update : OpenSSL (SUSE-SU-2015:1181-2) (Logjam)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL was updated to fix several security issues.

CVE-2015-4000: The Logjam Attack ( weakdh.org ) has been addressed by
rejecting connections with DH parameters shorter than 1024 bits. We
now also generate 2048-bit DH parameters by default.

CVE-2015-1788: Malformed ECParameters could cause an infinite loop.

CVE-2015-1789: An out-of-bounds read in X509_cmp_time was fixed.

CVE-2015-1790: A PKCS7 decoder crash with missing EnvelopedContent was
fixed.

fixed a timing side channel in RSA decryption (bnc#929678)

Additional changes :

In the default SSL cipher string EXPORT ciphers are now disabled. This
will only get active if applications get rebuilt and actually use this
string. (bnc#931698)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934491"
  );
  # https://download.suse.com/patch/finder/?keywords=9f7ad0f893ed0c841ceae726daca55cd
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfee53bc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1790.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4000.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151181-2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?564cd0d6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenSSL packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");
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
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"openssl-32bit-0.9.8a-18.92.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"openssl-devel-32bit-0.9.8a-18.92.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"openssl-32bit-0.9.8a-18.92.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"openssl-devel-32bit-0.9.8a-18.92.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"openssl-0.9.8a-18.92.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"openssl-devel-0.9.8a-18.92.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"openssl-doc-0.9.8a-18.92.1")) flag++;


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
