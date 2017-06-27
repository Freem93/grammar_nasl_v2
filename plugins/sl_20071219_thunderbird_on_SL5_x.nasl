#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60338);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL5.x, SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A cross-site scripting flaw was found in the way Thunderbird handled
the jar: URI scheme. It may be possible for a malicious HTML mail
message to leverage this flaw, and conduct a cross-site scripting
attack against a user running Thunderbird. (CVE-2007-5947)

Several flaws were found in the way Thunderbird processed certain
malformed HTML mail content. A HTML mail message containing malicious
content could cause Thunderbird to crash, or potentially execute
arbitrary code as the user running Thunderbird. (CVE-2007-5959)

A race condition existed when Thunderbird set the 'window.location'
property when displaying HTML mail content. This flaw could allow a
HTML mail message to set an arbitrary Referer header, which may lead
to a Cross-site Request Forgery (CSRF) attack against websites that
rely only on the Referer header for protection. (CVE-2007-5960)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0712&L=scientific-linux-errata&T=0&P=2386
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5f837f9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"thunderbird-1.5.0.12-7.el4")) flag++;

if (rpm_check(release:"SL5", reference:"thunderbird-1.5.0.12-7.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
