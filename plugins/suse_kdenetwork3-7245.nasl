#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51364);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-4776");

  script_name(english:"SuSE 10 Security Update : kdenetwork (ZYPP Patch Number 7245)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of kdenetwork fixes several bugs, the security related
issues are :

  - CWE-119 The included libgadu version allowed remote
    servers to cause a denial of service (crash) via a
    buffer over-read. (CVE-2008-4776: CVSS v2 Base Score:
    4.3 (AV:N/AC:M/Au:N/C:N/I:N/A:P))

Non-security issues :

  - kopete: ICQ login broken; login server changed.
    (bnc#653852)

  - kopete icq does not display nicknames correctly.
    (bnc#463442)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-4776.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7245.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"kdenetwork3-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdenetwork3-InstantMessenger-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdenetwork3-news-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"kdenetwork3-vnc-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-IRC-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-InstantMessenger-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-dialup-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-lan-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-lisa-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-news-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-query-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-vnc-3.5.1-32.34.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"kdenetwork3-wireless-3.5.1-32.34.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
