#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60665);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2408", "CVE-2009-2409", "CVE-2009-2654", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077");

  script_name(english:"Scientific Linux Security Update : seamonkey on SL3.x, SL4.x i386/x86_64");
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
"CVE-2009-2409 deprecate MD2 in SSL cert validation (Kaminsky)

CVE-2009-2408 firefox/nss: doesn't handle NULL in Common Name properly

CVE-2009-2654 firefox: URL bar spoofing vulnerability

CVE-2009-3072 Firefox 3.5.3 3.0.14 browser engine crashes

CVE-2009-3075 Firefox 3.5.2 3.0.14 JavaScript engine crashes

CVE-2009-3076 Firefox 3.0.14 Insufficient warning for PKCS11 module
installation and removal

CVE-2009-3077 Firefox 3.5.3 3.0.14 TreeColumns dangling pointer
vulnerability

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code with the privileges of the
user running SeaMonkey. (CVE-2009-3072, CVE-2009-3075)

A use-after-free flaw was found in SeaMonkey. An attacker could use
this flaw to crash SeaMonkey or, potentially, execute arbitrary code
with the privileges of the user running SeaMonkey. (CVE-2009-3077)

Dan Kaminsky discovered flaws in the way browsers such as SeaMonkey
handle NULL characters in a certificate. If an attacker is able to get
a carefully-crafted certificate signed by a Certificate Authority
trusted by SeaMonkey, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse SeaMonkey into
accepting it by mistake. (CVE-2009-2408)

Descriptions in the dialogs when adding and removing PKCS #11 modules
were not informative. An attacker able to trick a user into installing
a malicious PKCS #11 module could use this flaw to install their own
Certificate Authority certificates on a user's machine, making it
possible to trick the user into believing they are viewing a trusted
site or, potentially, execute arbitrary code with the privileges of
the user running SeaMonkey. (CVE-2009-3076)

A flaw was found in the way SeaMonkey displays the address bar when
window.open() is called in a certain way. An attacker could use this
flaw to conceal a malicious URL, possibly tricking a user into
believing they are viewing a trusted site. (CVE-2009-2654)

Dan Kaminsky found that browsers still accept certificates with MD2
hash signatures, even though MD2 is no longer considered a
cryptographically strong algorithm. This could make it easier for an
attacker to create a malicious certificate that would be treated as
trusted by a browser. NSS (provided by SeaMonkey) now disables the use
of MD2 and MD4 algorithms inside signatures by default.
(CVE-2009-2409)

After installing the update, SeaMonkey must be restarted for the
changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=850
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc11d588"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/09");
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
if (rpm_check(release:"SL3", reference:"seamonkey-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-chat-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-devel-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-dom-inspector-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-js-debugger-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-mail-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nspr-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nspr-devel-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nss-1.0.9-0.45.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nss-devel-1.0.9-0.45.el3")) flag++;

if (rpm_check(release:"SL4", reference:"seamonkey-1.0.9-48.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-chat-1.0.9-48.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-devel-1.0.9-48.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-dom-inspector-1.0.9-48.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-js-debugger-1.0.9-48.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-mail-1.0.9-48.el4_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
