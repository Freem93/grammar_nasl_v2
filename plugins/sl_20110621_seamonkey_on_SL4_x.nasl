#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61072);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/27 17:06:04 $");

  script_cve_id("CVE-2011-0083", "CVE-2011-2362", "CVE-2011-2364", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2377");

  script_name(english:"Scientific Linux Security Update : seamonkey on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SeaMonkey is an open source web browser, email and newsgroup client,
IRC chat client, and HTML editor.

A flaw was found in the way SeaMonkey handled malformed JPEG images. A
website containing a malicious JPEG image could cause SeaMonkey to
crash or, potentially, execute arbitrary code with the privileges of
the user running SeaMonkey. (CVE-2011-2377)

Multiple dangling pointer flaws were found in SeaMonkey. A web page
containing malicious content could cause SeaMonkey to crash or,
potentially, execute arbitrary code with the privileges of the user
running SeaMonkey. (CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code with the privileges of the
user running SeaMonkey. (CVE-2011-2364, CVE-2011-2365, CVE-2011-2374,
CVE-2011-2375, CVE-2011-2376)

An integer overflow flaw was found in the way SeaMonkey handled
JavaScript Array objects. A website containing malicious JavaScript
could cause SeaMonkey to execute that JavaScript with the privileges
of the user running SeaMonkey. (CVE-2011-2371)

A use-after-free flaw was found in the way SeaMonkey handled malformed
JavaScript. A website containing malicious JavaScript could cause
SeaMonkey to execute that JavaScript with the privileges of the user
running SeaMonkey. (CVE-2011-2373)

It was found that SeaMonkey could treat two separate cookies as
interchangeable if both were for the same domain name but one of those
domain names had a trailing '.' character. This violates the
same-origin policy and could possibly lead to data being leaked to the
wrong domain. (CVE-2011-2362)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=4239
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?012cdf6a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Array.reduceRight() Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"seamonkey-1.0.9-71.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-chat-1.0.9-71.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-devel-1.0.9-71.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-dom-inspector-1.0.9-71.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-js-debugger-1.0.9-71.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-mail-1.0.9-71.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
