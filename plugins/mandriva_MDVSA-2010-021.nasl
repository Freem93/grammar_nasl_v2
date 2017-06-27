#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:021. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(44102);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/01/27 00:45:21 $");

  script_cve_id("CVE-2009-4022", "CVE-2010-0097", "CVE-2010-0290", "CVE-2010-0382");
  script_bugtraq_id(37118, 37865);
  script_xref(name:"MDVSA", value:"2010:021");

  script_name(english:"Mandriva Linux Security Advisory : bind (MDVSA-2010:021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Some vulnerabilities were discovered and corrected in bind :

The original fix for CVE-2009-4022 was found to be incomplete. BIND
was incorrectly caching certain responses without performing proper
DNSSEC validation. CNAME and DNAME records could be cached, without
proper DNSSEC validation, when received from processing recursive
client queries that requested DNSSEC records but indicated that
checking should be disabled. A remote attacker could use this flaw to
bypass the DNSSEC validation check and perform a cache poisoning
attack if the target BIND server was receiving such client queries
(CVE-2010-0290).

There was an error in the DNSSEC NSEC/NSEC3 validation code that could
cause bogus NXDOMAIN responses (that is, NXDOMAIN responses for
records proven by NSEC or NSEC3 to exist) to be cached as if they had
validated correctly, so that future queries to the resolver would
return the bogus NXDOMAIN with the AD flag set (CVE-2010-0097).

ISC BIND 9.0.x through 9.3.x, 9.4 before 9.4.3-P5, 9.5 before
9.5.2-P2, 9.6 before 9.6.1-P3, and 9.7.0 beta handles out-of-bailiwick
data accompanying a secure response without re-fetching from the
original source, which allows remote attackers to have an unspecified
impact via a crafted response, aka Bug 20819. NOTE: this vulnerability
exists because of a regression during the fix for CVE-2009-4022
(CVE-2010-0382).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

Additionally BIND has been upgraded to the latest patch release
version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=557121"
  );
  # https://www.isc.org/advisories/CVE-2009-4022v6
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bind-announce&m=126392310412888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.isc.org/advisories/CVE-2010-0097"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2008.0", reference:"bind-9.4.3-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"bind-devel-9.4.3-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"bind-utils-9.4.3-0.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"bind-9.5.2-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"bind-devel-9.5.2-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"bind-doc-9.5.2-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"bind-utils-9.5.2-0.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"bind-9.6.1-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"bind-devel-9.6.1-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"bind-doc-9.6.1-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"bind-utils-9.6.1-0.2mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"bind-9.6.1-4.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"bind-devel-9.6.1-4.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"bind-doc-9.6.1-4.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"bind-utils-9.6.1-4.2mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
