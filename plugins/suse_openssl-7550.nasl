#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57234);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2011-1945");

  script_name(english:"SuSE 10 Security Update : OpenSSL (ZYPP Patch Number 7550)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of openssl fixes a timing attack. This attack can be used
to obtain the private key of a TLS server whenever ECDSA signatures
are used. CVE-2011-1945: CVSS v2 Base Score: 4.3 (important)
(AV:N/AC:M/Au:N/C:P/I:N/A:N): Cryptographic Issues. (CWE-310)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1945.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7550.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"openssl-0.9.8a-18.52.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"openssl-devel-0.9.8a-18.52.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"openssl-32bit-0.9.8a-18.52.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"openssl-devel-32bit-0.9.8a-18.52.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"openssl-0.9.8a-18.52.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"openssl-devel-0.9.8a-18.52.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"openssl-doc-0.9.8a-18.52.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"openssl-32bit-0.9.8a-18.52.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"openssl-devel-32bit-0.9.8a-18.52.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
