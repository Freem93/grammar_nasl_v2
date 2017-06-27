#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60750);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-1571", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2466", "CVE-2009-2470", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3274", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3979", "CVE-2010-0159");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2009-2462,
CVE-2009-2463, CVE-2009-2466, CVE-2009-3072, CVE-2009-3075,
CVE-2009-3380, CVE-2009-3979, CVE-2010-0159)

A use-after-free flaw was found in Thunderbird. An attacker could use
this flaw to crash Thunderbird or, potentially, execute arbitrary code
with the privileges of the user running Thunderbird. (CVE-2009-3077)

A heap-based buffer overflow flaw was found in the Thunderbird string
to floating point conversion routines. An HTML mail message containing
malicious JavaScript could crash Thunderbird or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2009-0689)

A use-after-free flaw was found in Thunderbird. Under low memory
conditions, viewing an HTML mail message containing malicious content
could result in Thunderbird executing arbitrary code with the
privileges of the user running Thunderbird. (CVE-2009-1571)

A flaw was found in the way Thunderbird created temporary file names
for downloaded files. If a local attacker knows the name of a file
Thunderbird is going to download, they can replace the contents of
that file with arbitrary contents. (CVE-2009-3274)

A flaw was found in the way Thunderbird displayed a right-to-left
override character when downloading a file. In these cases, the name
displayed in the title bar differed from the name displayed in the
dialog body. An attacker could use this flaw to trick a user into
downloading a file that has a file name or extension that is different
from what the user expected. (CVE-2009-3376)

A flaw was found in the way Thunderbird processed SOCKS5 proxy
replies. A malicious SOCKS5 server could send a specially crafted
reply that would cause Thunderbird to crash. (CVE-2009-2470)

Descriptions in the dialogs when adding and removing PKCS #11 modules
were not informative. An attacker able to trick a user into installing
a malicious PKCS #11 module could use this flaw to install their own
Certificate Authority certificates on a user's machine, making it
possible to trick the user into believing they are viewing trusted
content or, potentially, execute arbitrary code with the privileges of
the user running Thunderbird. (CVE-2009-3076)

All running instances of Thunderbird must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=1516
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e6c04be"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 94, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/17");
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
if (rpm_check(release:"SL4", reference:"thunderbird-1.5.0.12-25.el4")) flag++;

if (rpm_check(release:"SL5", reference:"thunderbird-2.0.0.24-2.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
