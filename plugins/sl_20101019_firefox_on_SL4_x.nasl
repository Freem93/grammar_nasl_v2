#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60870);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-3170", "CVE-2010-3173", "CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183");

  script_name(english:"Scientific Linux Security Update : firefox on SL4.x, SL5.x i386/x86_64");
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
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-3175, CVE-2010-3176, CVE-2010-3179,
CVE-2010-3183, CVE-2010-3180)

A flaw was found in the way the Gopher parser in Firefox converted
text into HTML. A malformed file name on a Gopher server could, when
accessed by a victim running Firefox, allow arbitrary JavaScript to be
executed in the context of the Gopher domain. (CVE-2010-3177)

A same-origin policy bypass flaw was found in Firefox. An attacker
could create a malicious web page that, when viewed by a victim, could
steal private data from a different website the victim has loaded with
Firefox. (CVE-2010-3178)

A flaw was found in the script that launches Firefox. The
LD_LIBRARY_PATH variable was appending a '.' character, which could
allow a local attacker to execute arbitrary code with the privileges
of a different user running Firefox, if that user ran Firefox from
within an attacker-controlled directory. (CVE-2010-3182)

This update also provides NSS version 3.12.8 which is required by the
updated Firefox version, fixing the following security issues :

It was found that the SSL DHE (Diffie-Hellman Ephemeral) mode
implementation for key exchanges in Firefox accepted DHE keys that
were 256 bits in length. This update removes support for 256 bit DHE
keys, as such keys are easily broken using modern hardware.
(CVE-2010-3173)

A flaw was found in the way NSS matched SSL certificates when the
certificates had a Common Name containing a wildcard and a partial IP
address. NSS incorrectly accepted connections to IP addresses that
fell within the SSL certificate's wildcard range as valid SSL
connections, possibly allowing an attacker to conduct a
man-in-the-middle attack. (CVE-2010-3170)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1010&L=scientific-linux-errata&T=0&P=1993
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a72c4974"
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
if (rpm_check(release:"SL4", reference:"firefox-3.6.11-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-3.12.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-devel-3.12.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-tools-3.12.8-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.6.11-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-3.12.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.12.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.12.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.12.8-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.11-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.11-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
