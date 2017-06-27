#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60822);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1205", "CVE-2010-1211", "CVE-2010-1214", "CVE-2010-2753", "CVE-2010-2754");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A memory corruption flaw was found in the way Thunderbird decoded
certain PNG images. An attacker could create a mail message containing
a specially crafted PNG image that, when opened, could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2010-1205)

Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2010-0174,
CVE-2010-1200, CVE-2010-1211, CVE-2010-1214, CVE-2010-2753)

An integer overflow flaw was found in the processing of malformed HTML
mail content. An HTML mail message containing malicious content could
cause Thunderbird to crash or, potentially, execute arbitrary code
with the privileges of the user running Thunderbird. (CVE-2010-1199)

Several use-after-free flaws were found in Thunderbird. Viewing an
HTML mail message containing malicious content could result in
Thunderbird executing arbitrary code with the privileges of the user
running Thunderbird. (CVE-2010-0175, CVE-2010-0176, CVE-2010-0177)

A flaw was found in the way Thunderbird plug-ins interact. It was
possible for a plug-in to reference the freed memory from a different
plug-in, resulting in the execution of arbitrary code with the
privileges of the user running Thunderbird. (CVE-2010-1198)

A flaw was found in the way Thunderbird handled the
'Content-Disposition: attachment' HTTP header when the 'Content-Type:
multipart' HTTP header was also present. Loading remote HTTP content
that allows arbitrary uploads and relies on the 'Content-Disposition:
attachment' HTTP header to prevent content from being displayed
inline, could be used by an attacker to serve malicious content to
users. (CVE-2010-1197)

A same-origin policy bypass flaw was found in Thunderbird. Remote HTML
content could steal private data from different remote HTML content
Thunderbird has loaded. (CVE-2010-2754)

All running instances of Thunderbird must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=2494
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63e87b4c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL5", reference:"thunderbird-2.0.0.24-6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
