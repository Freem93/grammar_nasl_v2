#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60827);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-2251");

  script_name(english:"Scientific Linux Security Update : lftp for SL 5");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LFTP is a sophisticated file transfer program for the FTP and HTTP
protocols. Like Bash, it has job control and uses the Readline library
for input. It has bookmarks, built-in mirroring, and can transfer
several files in parallel. It is designed with reliability in mind.

It was discovered that lftp trusted the file name provided in the
Content-Disposition HTTP header. A malicious HTTP server could use
this flaw to write or overwrite files in the current working directory
of a victim running lftp, by sending a different file from what the
victim requested. (CVE-2010-2251)

To correct this flaw, the following changes were made to lftp: the
'xfer:clobber' option now defaults to 'no', causing lftp to not
overwrite existing files, and a new option, 'xfer:auto-rename', which
defaults to 'no', has been introduced to control whether lftp should
use server-suggested file names. Refer to the 'Settings' section of
the lftp(1) manual page for additional details on changing lftp
settings.

All lftp users should upgrade to this updated package, which contains
a backported patch to correct this issue."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=184
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1606f2b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lftp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/02");
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
if (rpm_check(release:"SL5", reference:"lftp-3.7.11-4.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
