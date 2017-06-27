#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49859);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2012/06/14 20:29:54 $");

  script_cve_id("CVE-2008-5349", "CVE-2009-2625");

  script_name(english:"SuSE 10 Security Update : IBM Java 1.4.2 (ZYPP Patch Number 6523)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.4.2 was updated to SR13 FP1.

It fixes following two security issues: CVE-2009-2625: A vulnerability
in the Java Runtime Environment (JRE) with parsing XML data might
allow a remote client to create a denial-of-service condition on the
system that the JRE runs on.

  - A vulnerability in how the Java Runtime Environment
    (JRE) handles certain RSA public keys might cause the
    JRE to consume an excessive amount of CPU resources.
    This might lead to a Denial of Service (DoS) condition
    on affected systems. Such keys could be provided by a
    remote client of an application. (CVE-2008-5349)

This issue affects the following security providers: IBMJCE,
IBMPKCS11Impl and IBMJCEFIPS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5349.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2625.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6523.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_4_2-ibm-1.4.2_sr13.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_4_2-ibm-devel-1.4.2_sr13.1-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr13.1-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
