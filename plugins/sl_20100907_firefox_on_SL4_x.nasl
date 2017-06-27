#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60849);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");

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
running Firefox. (CVE-2010-3169, CVE-2010-2762)

Several use-after-free and dangling pointer flaws were found in
Firefox. A web page containing malicious content could cause Firefox
to crash or, potentially, execute arbitrary code with the privileges
of the user running Firefox. (CVE-2010-2760, CVE-2010-2766,
CVE-2010-2767, CVE-2010-3167, CVE-2010-3168)

Multiple buffer overflow flaws were found in Firefox. A web page
containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-2765, CVE-2010-3166)

Multiple cross-site scripting (XSS) flaws were found in Firefox. A web
page containing malicious content could cause Firefox to run
JavaScript code with the permissions of a different website.
(CVE-2010-2768, CVE-2010-2769)

A flaw was found in the Firefox XMLHttpRequest object. A remote site
could use this flaw to gather information about servers on an internal
private network. (CVE-2010-2764)

Note: After installing this update, Firefox will fail to connect (with
HTTPS) to a server using the SSL DHE (Diffie-Hellman Ephemeral) key
exchange if the server's ephemeral key is too small. Connecting to
such servers is a security risk as an ephemeral key that is too small
makes the SSL connection vulnerable to attack.

If you encounter the condition where Firefox fails to connect to a
server that has an ephemeral key that is too small, you can try
connecting using a cipher suite with a different key exchange
algorithm by disabling all DHE cipher suites in Firefox :

1) Type about:config in the URL bar and press the Enter key. 2) In the
Filter search bar, type ssl3.dhe 3) For all preferences now presented,
double-click the true value to change the value to false. 4) This
change would affect connections to all HTTPS servers.

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1009&L=scientific-linux-errata&T=0&P=892
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89b9744b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
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
if (rpm_check(release:"SL4", reference:"firefox-3.6.9-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-4.8.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-devel-4.8.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-3.12.7-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-devel-3.12.7-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-tools-3.12.7-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.6.9-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-4.8.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-devel-4.8.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-3.12.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.12.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.12.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.12.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.9-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.9-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
