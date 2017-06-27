#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60413);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-1105");

  script_name(english:"Scientific Linux Security Update : samba on SL5.x i386/x86_64");
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
"A heap-based buffer overflow flaw was found in the way Samba clients
handle over-sized packets. If a client connected to a malicious Samba
server, it was possible to execute arbitrary code as the Samba client
user. It was also possible for a remote user to send a specially
crafted print request to a Samba server that could result in the
server executing the vulnerable client code, resulting in arbitrary
code execution with the permissions of the Samba server.
(CVE-2008-1105)

This update also addresses two issues which prevented Samba from
joining certain Windows domains with tightened security policies, and
prevented certain signed SMB content from working as expected :

  - when some Windows&reg; 2000-based domain controllers
    were set to use mandatory signing, Samba clients would
    drop the connection because of an error when generating
    signatures. This presented as a 'Server packet had
    invalid SMB signature' error to the Samba client. This
    update corrects the signature generation error.

  - Samba servers using the 'net ads join' command to
    connect to a Windows Server&reg; 2003-based domain would
    fail with 'failed to get schannel session key from
    server' and 'NT_STATUS_ACCESS_DENIED' errors. This
    update correctly binds to the NETLOGON share, allowing
    Samba servers to connect to the domain properly."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0805&L=scientific-linux-errata&T=0&P=2922
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f91de3f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/28");
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
if (rpm_check(release:"SL5", reference:"samba-3.0.28-1.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"samba-client-3.0.28-1.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"samba-common-3.0.28-1.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"samba-swat-3.0.28-1.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
