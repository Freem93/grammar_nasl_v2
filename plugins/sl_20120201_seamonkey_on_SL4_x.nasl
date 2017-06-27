#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61233);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/06 11:47:00 $");

  script_cve_id("CVE-2011-3670", "CVE-2012-0442");

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
"SeaMonkey is an open source web browser, e-mail and newsgroup client,
IRC chat client, and HTML editor.

A flaw was found in the processing of malformed web content. A web
page containing malicious content could cause SeaMonkey to crash or,
potentially, execute arbitrary code with the privileges of the user
running SeaMonkey. (CVE-2012-0442)

The same-origin policy in SeaMonkey treated http://example.com and
http://[example.com] as interchangeable. A malicious script could
possibly use this flaw to gain access to sensitive information (such
as a client's IP and user e-mail address, or httpOnly cookies) that
may be included in HTTP proxy error replies, generated in response to
invalid URLs using square brackets. (CVE-2011-3670)

All SeaMonkey users should upgrade to these updated packages, which
correct these issues. After installing the update, SeaMonkey must be
restarted for the changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?552bcb3e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/01");
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
if (rpm_check(release:"SL4", reference:"seamonkey-1.0.9-78.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-chat-1.0.9-78.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-debuginfo-1.0.9-78.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-devel-1.0.9-78.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-dom-inspector-1.0.9-78.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-js-debugger-1.0.9-78.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-mail-1.0.9-78.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
