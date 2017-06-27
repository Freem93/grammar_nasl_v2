#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60872);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-3170", "CVE-2010-3173", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3180", "CVE-2010-3182");

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
"Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code with the privileges of the
user running SeaMonkey. (CVE-2010-3176, CVE-2010-3180)

A flaw was found in the way the Gopher parser in SeaMonkey converted
text into HTML. A malformed file name on a Gopher server could, when
accessed by a victim running SeaMonkey, allow arbitrary JavaScript to
be executed in the context of the Gopher domain. (CVE-2010-3177)

A flaw was found in the script that launches SeaMonkey. The
LD_LIBRARY_PATH variable was appending a '.' character, which could
allow a local attacker to execute arbitrary code with the privileges
of a different user running SeaMonkey, if that user ran SeaMonkey from
within an attacker-controlled directory. (CVE-2010-3182)

It was found that the SSL DHE (Diffie-Hellman Ephemeral) mode
implementation for key exchanges in SeaMonkey accepted DHE keys that
were 256 bits in length. This update removes support for 256 bit DHE
keys, as such keys are easily broken using modern hardware.
(CVE-2010-3173)

A flaw was found in the way SeaMonkey matched SSL certificates when
the certificates had a Common Name containing a wildcard and a partial
IP address. SeaMonkey incorrectly accepted connections to IP addresses
that fell within the SSL certificate's wildcard range as valid SSL
connections, possibly allowing an attacker to conduct a
man-in-the-middle attack. (CVE-2010-3170)

After installing the update, SeaMonkey must be restarted for the
changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1010&L=scientific-linux-errata&T=0&P=2260
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce5019e4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"seamonkey-1.0.9-64.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-chat-1.0.9-64.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-devel-1.0.9-64.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-dom-inspector-1.0.9-64.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-js-debugger-1.0.9-64.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-mail-1.0.9-64.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
