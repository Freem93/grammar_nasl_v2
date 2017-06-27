#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60589);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376");

  script_name(english:"Scientific Linux Security Update : pidgin on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"A buffer overflow flaw was found in the way Pidgin initiates file
transfers when using the Extensible Messaging and Presence Protocol
(XMPP). If a Pidgin client initiates a file transfer, and the remote
target sends a malformed response, it could cause Pidgin to crash or,
potentially, execute arbitrary code with the permissions of the user
running Pidgin. This flaw only affects accounts using XMPP, such as
Jabber and Google Talk. (CVE-2009-1373)

A denial of service flaw was found in Pidgin's QQ protocol decryption
handler. When the QQ protocol decrypts packet information, heap data
can be overwritten, possibly causing Pidgin to crash. (CVE-2009-1374)

A flaw was found in the way Pidgin's PurpleCircBuffer object is
expanded. If the buffer is full when more data arrives, the data
stored in this buffer becomes corrupted. This corrupted data could
result in confusing or misleading data being presented to the user, or
possibly crash Pidgin. (CVE-2009-1375)

If a Pidgin client receives a specially crafted MSN message, it may be
possible to execute arbitrary code with the permissions of the user
running Pidgin. (CVE-2009-1376)

Note: By default, when using an MSN account, only users on your buddy
list can send you messages. This prevents arbitrary MSN users from
exploiting this flaw.

Pidgin must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0905&L=scientific-linux-errata&T=0&P=1651
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c2981043"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/22");
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
if (rpm_check(release:"SL3", reference:"pidgin-1.5.1-3.el3")) flag++;

if (rpm_check(release:"SL4", reference:"finch-2.5.5-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"finch-devel-2.5.5-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-2.5.5-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-devel-2.5.5-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-perl-2.5.5-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-tcl-2.5.5-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-2.5.5-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-devel-2.5.5-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-perl-2.5.5-2.el4")) flag++;

if (rpm_check(release:"SL5", reference:"finch-2.5.5-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.5.5-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.5.5-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.5.5-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.5.5-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.5.5-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.5.5-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.5.5-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.5.5-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
