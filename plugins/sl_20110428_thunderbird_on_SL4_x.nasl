#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61028);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:26 $");

  script_cve_id("CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL4.x,SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed HTML content.
An HTML mail message containing malicious content could possibly lead
to arbitrary code execution with the privileges of the user running
Thunderbird. (CVE-2011-0080)

An arbitrary memory write flaw was found in the way Thunderbird
handled out-of-memory conditions. If all memory was consumed when a
user viewed a malicious HTML mail message, it could possibly lead to
arbitrary code execution with the privileges of the user running
Thunderbird. (CVE-2011-0078)

An integer overflow flaw was found in the way Thunderbird handled the
HTML frameset tag. An HTML mail message with a frameset tag containing
large values for the 'rows' and 'cols' attributes could trigger this
flaw, possibly leading to arbitrary code execution with the privileges
of the user running Thunderbird. (CVE-2011-0077)

A flaw was found in the way Thunderbird handled the HTML iframe tag.
An HTML mail message with an iframe tag containing a specially crafted
source address could trigger this flaw, possibly leading to arbitrary
code execution with the privileges of the user running Thunderbird.
(CVE-2011-0075)

A flaw was found in the way Thunderbird displayed multiple marquee
elements. A malformed HTML mail message could cause Thunderbird to
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2011-0074)

A flaw was found in the way Thunderbird handled the nsTreeSelection
element. Malformed content could cause Thunderbird to execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2011-0073)

All Thunderbird users should upgrade to this updated package, which
resolves these issues. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=3607
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61f6bbdf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
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
if (rpm_check(release:"SL4", reference:"thunderbird-1.5.0.12-38.el4")) flag++;

if (rpm_check(release:"SL5", reference:"thunderbird-2.0.0.24-17.el5_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
