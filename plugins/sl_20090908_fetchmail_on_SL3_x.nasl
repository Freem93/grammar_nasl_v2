#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60662);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2007-4565", "CVE-2008-2711", "CVE-2009-2666");

  script_name(english:"Scientific Linux Security Update : fetchmail on SL3.x, SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2007-4565 Fetchmail NULL pointer dereference

CVE-2008-2711 fetchmail: Crash in large log messages in verbose mode

CVE-2009-2666 fetchmail: SSL null terminator bypass

It was discovered that fetchmail is affected by the previously
published 'null prefix attack', caused by incorrect handling of NULL
characters in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse fetchmail into
accepting it by mistake. (CVE-2009-2666)

A flaw was found in the way fetchmail handles rejections from a remote
SMTP server when sending warning mail to the postmaster. If fetchmail
sent a warning mail to the postmaster of an SMTP server and that SMTP
server rejected it, fetchmail could crash. (CVE-2007-4565)

A flaw was found in fetchmail. When fetchmail is run in double verbose
mode ('-v -v'), it could crash upon receiving certain, malformed mail
messages with long headers. A remote attacker could use this flaw to
cause a denial of service if fetchmail was also running in daemon mode
('-d'). (CVE-2008-2711)

If fetchmail is running in daemon mode, it must be restarted for this
update to take effect (use the 'fetchmail --quit' command to stop the
fetchmail process)."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=329
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2d44ad8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fetchmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
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
if (rpm_check(release:"SL3", reference:"fetchmail-6.2.0-3.el3.5")) flag++;

if (rpm_check(release:"SL4", reference:"fetchmail-6.2.5-6.0.1.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"fetchmail-6.3.6-1.1.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
