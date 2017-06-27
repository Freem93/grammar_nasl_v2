#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60667);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2473", "CVE-2009-2474");

  script_name(english:"Scientific Linux Security Update : neon on SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-2473 neon, gnome-vfs2 embedded neon: billion laughs DoS
attack

CVE-2009-2474 neon: Improper verification of x509v3 certificate with
NULL (zero) byte in certain fields

It was discovered that neon is affected by the previously published
'null prefix attack', caused by incorrect handling of NULL characters
in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse an application using
the neon library into accepting it by mistake. (CVE-2009-2474)

A denial of service flaw was found in the neon Extensible Markup
Language (XML) parser. A remote attacker (malicious DAV server) could
provide a specially crafted XML document that would cause excessive
memory and CPU consumption if an application using the neon XML parser
was tricked into processing it. (CVE-2009-2473)

Applications using the neon HTTP and WebDAV client library, such as
cadaver, must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=1927
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?881b947f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected neon and / or neon-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/21");
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
if (rpm_check(release:"SL4", reference:"neon-0.24.7-4.el4_8.2")) flag++;
if (rpm_check(release:"SL4", reference:"neon-devel-0.24.7-4.el4_8.2")) flag++;

if (rpm_check(release:"SL5", reference:"neon-0.25.5-10.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"neon-devel-0.25.5-10.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
