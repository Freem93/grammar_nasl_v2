#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60914);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-2948", "CVE-2010-2949");

  script_name(english:"Scientific Linux Security Update : quagga on SL6.x i386/x86_64");
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
"A stack-based buffer overflow flaw was found in the way the Quagga
bgpd daemon processed certain BGP Route Refresh (RR) messages. A
configured BGP peer could send a specially crafted BGP message,
causing bgpd on a target system to crash or, possibly, execute
arbitrary code with the privileges of the user running bgpd.
(CVE-2010-2948)

Note: On Scientific Linux 6 it is not possible to exploit
CVE-2010-2948 to run arbitrary code as the overflow is blocked by
FORTIFY_SOURCE.

A NULL pointer dereference flaw was found in the way the Quagga bgpd
daemon parsed the paths of autonomous systems (AS). A configured BGP
peer could crash bgpd on a target system via a specially crafted BGP
message. (CVE-2010-2949)

After installing the updated packages, the bgpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=4420
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e73ab6b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected quagga, quagga-contrib and / or quagga-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/06");
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
if (rpm_check(release:"SL6", reference:"quagga-0.99.15-5.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"quagga-contrib-0.99.15-5.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"quagga-devel-0.99.15-5.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
