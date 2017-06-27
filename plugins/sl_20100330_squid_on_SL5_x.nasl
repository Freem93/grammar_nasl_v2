#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60775);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:08 $");

  script_cve_id("CVE-2009-2855", "CVE-2010-0308");

  script_name(english:"Scientific Linux Security Update : squid on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way Squid processed certain external ACL
helper HTTP header fields that contained a delimiter that was not a
comma. A remote attacker could issue a crafted request to the Squid
server, causing excessive CPU use (up to 100%). (CVE-2009-2855)

Note: The CVE-2009-2855 issue only affected non-default configurations
that use an external ACL helper script.

A flaw was found in the way Squid handled truncated DNS replies. A
remote attacker able to send specially crafted UDP packets to Squid's
DNS client port could trigger an assertion failure in Squid's child
process, causing that child process to exit. (CVE-2010-0308)

This update also fixes the following bugs :

  - Squid's init script returns a non-zero value when trying
    to stop a stopped service. This is not LSB compliant and
    can generate difficulties in cluster environments. This
    update makes stopping LSB compliant. (BZ#521926)

  - Squid is not currently built to support MAC address
    filtering in ACLs. This update includes support for MAC
    address filtering. (BZ#496170)

  - Squid is not currently built to support Kerberos
    negotiate authentication. This update enables Kerberos
    authentication. (BZ#516245)

  - Squid does not include the port number as part of URIs
    it constructs when configured as an accelerator. This
    results in a 403 error. This update corrects this
    behavior. (BZ#538738)

  - the error_map feature does not work if the same handling
    is set also on the HTTP server that operates in deflate
    mode. This update fixes this issue. (BZ#470843)

After installing this update, the squid service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=678
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1c37ebc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=516245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=521926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=538738"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"squid-2.6.STABLE21-6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
