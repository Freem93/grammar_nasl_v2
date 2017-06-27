#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60649);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-2957", "CVE-2009-2958");

  script_name(english:"Scientific Linux Security Update : dnsmasq on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2009-2957, CVE-2009-2958 dnsmasq: multiple vulnerabilities in TFTP
server

Core Security Technologies discovered a heap overflow flaw in dnsmasq
when the TFTP service is enabled (the '--enable-tftp' command line
option, or by enabling 'enable-tftp' in '/etc/dnsmasq.conf'). If the
configured tftp-root is sufficiently long, and a remote user sends a
request that sends a long file name, dnsmasq could crash or, possibly,
execute arbitrary code with the privileges of the dnsmasq service
(usually the unprivileged 'nobody' user). (CVE-2009-2957)

A NULL pointer dereference flaw was discovered in dnsmasq when the
TFTP service is enabled. This flaw could allow a malicious TFTP client
to crash the dnsmasq service. (CVE-2009-2958)

Note: The default tftp-root is '/var/ftpd', which is short enough to
make it difficult to exploit the CVE-2009-2957 issue; if a longer
directory name is used, arbitrary code execution may be possible. As
well, the dnsmasq package distributed by Red Hat does not have TFTP
support enabled by default.

After installing the updated package, the dnsmasq service must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=80
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b50cab73"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dnsmasq package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/31");
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
if (rpm_check(release:"SL5", reference:"dnsmasq-2.45-1.1.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
