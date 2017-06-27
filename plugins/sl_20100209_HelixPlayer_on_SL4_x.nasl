#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60729);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/17 04:31:38 $");

  script_cve_id("CVE-2009-4242", "CVE-2009-4245", "CVE-2009-4247", "CVE-2009-4248", "CVE-2009-4257", "CVE-2010-0416", "CVE-2010-0417");
  script_xref(name:"IAVA", value:"2010-A-0022");

  script_name(english:"Scientific Linux Security Update : HelixPlayer on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple buffer and integer overflow flaws were found in the way
HelixPlayer processed Graphics Interchange Format (GIF) files. An
attacker could create a specially crafted GIF file which would cause
HelixPlayer to crash or, potentially, execute arbitrary code when
opened. (CVE-2009-4242, CVE-2009-4245)

A buffer overflow flaw was found in the way HelixPlayer processed
Synchronized Multimedia Integration Language (SMIL) files. An attacker
could create a specially crafted SMIL file which would cause
HelixPlayer to crash or, potentially, execute arbitrary code when
opened. (CVE-2009-4257)

A buffer overflow flaw was found in the way HelixPlayer handled the
Real Time Streaming Protocol (RTSP) SET_PARAMETER directive. A
malicious RTSP server could use this flaw to crash HelixPlayer or,
potentially, execute arbitrary code. (CVE-2009-4248)

Multiple buffer overflow flaws were discovered in the way HelixPlayer
handled RuleBook structures in media files and RTSP streams. Specially
crafted input could cause HelixPlayer to crash or, potentially,
execute arbitrary code. (CVE-2009-4247, CVE-2010-0417)

A buffer overflow flaw was found in the way HelixPlayer performed URL
un-escaping. A specially crafted URL string could cause HelixPlayer to
crash or, potentially, execute arbitrary code. (CVE-2010-0416)

All running instances of HelixPlayer must be restarted for this update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1002&L=scientific-linux-errata&T=0&P=645
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ac0ef0a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected HelixPlayer package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"HelixPlayer-1.0.6-1.el4_8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
