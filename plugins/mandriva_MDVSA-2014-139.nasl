#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:139. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(76885);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/05 23:53:27 $");

  script_cve_id("CVE-2014-1544");
  script_bugtraq_id(68816);
  script_xref(name:"MDVSA", value:"2014:139");

  script_name(english:"Mandriva Linux Security Advisory : nss (MDVSA-2014:139)");
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
"A vulnerability has been found and corrected in mozilla NSS :

Use-after-free vulnerability in the CERT_DestroyCertificate function
in libnss3.so in Mozilla Network Security Services (NSS) 3.x, as used
in Firefox before 31.0, Firefox ESR 24.x before 24.7, and Thunderbird
before 24.7, allows remote attackers to execute arbitrary code via
vectors that trigger certain improper removal of an NSSCertificate
structure from a trust domain (CVE-2014-1544).

The updated packages have been upgraded to the latest NSS (3.16.3)
versions which is not vulnerable to this issue.

The nss 3.16.1 update done as part of MDVSA-2014:125 introduced a
regression because of the upstream change: 'Imposed name constraints
on the French government root CA ANSSI (DCISS)' The change wont work
as currently implemented as the French government root CA signs more
than 'gouv.fr' domains. So for now we revert that change until its
properly fixed upstream (mga#13563).

Additionally the rootcerts package has also been updated to the latest
version as of 2014-07-03, which adds, removes, and distrusts several
certificates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGAA-2014-0135.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.mageia.org/show_bug.cgi?id=13563"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.16.2_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9bc9e12"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.16.3_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0ee8a6e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2014/mfsa2014-63.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss-devel-3.16.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss-static-devel-3.16.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss3-3.16.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nss-3.16.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"nss-doc-3.16.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rootcerts-20140703.00-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rootcerts-java-20140703.00-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
