#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:244. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(79989);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/16 15:13:15 $");

  script_cve_id("CVE-2013-1794", "CVE-2013-1795", "CVE-2013-4134", "CVE-2013-4135", "CVE-2014-0159");
  script_bugtraq_id(58299, 58300, 61438, 61439, 66776);
  script_xref(name:"MDVSA", value:"2014:244");

  script_name(english:"Mandriva Linux Security Advisory : openafs (MDVSA-2014:244)");
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
"Multiple vulnerabilities has been found and corrected in openafs :

Buffer overflow in certain client utilities in OpenAFS before 1.6.2
allows remote authenticated users to cause a denial of service (crash)
and possibly execute arbitrary code via a long fileserver ACL entry
(CVE-2013-1794).

Integer overflow in ptserver in OpenAFS before 1.6.2 allows remote
attackers to cause a denial of service (crash) via a large list from
the IdToName RPC, which triggers a heap-based buffer overflow
(CVE-2013-1795).

OpenAFS before 1.4.15, 1.6.x before 1.6.5, and 1.7.x before 1.7.26
uses weak encryption (DES) for Kerberos keys, which makes it easier
for remote attackers to obtain the service key (CVE-2013-4134).

The vos command in OpenAFS 1.6.x before 1.6.5, when using the -encrypt
option, only enables integrity protection and sends data in cleartext,
which allows remote attackers to obtain sensitive information by
sniffing the network (CVE-2013-4135).

Buffer overflow in the GetStatistics64 remote procedure call (RPC) in
OpenAFS 1.4.8 before 1.6.7 allows remote attackers to cause a denial
of service (crash) via a crafted statsVersion argument
(CVE-2014-0159).

A denial of service flaw was found in libxml2, a library providing
support to read, modify and write XML and HTML files. A remote
attacker could provide a specially crafted XML file that, when
processed by an application using libxml2, would lead to excessive CPU
consumption (denial of service) based on excessive entity
substitutions, even if entity substitution was disabled, which is the
parser default behavior (CVE-2014-3660).

The updated packages have been upgraded to the 1.4.15 version and
patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openafs.org/pages/security/OPENAFS-SA-2013-001.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openafs.org/pages/security/OPENAFS-SA-2013-002.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openafs.org/pages/security/OPENAFS-SA-2013-003.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openafs.org/pages/security/OPENAFS-SA-2013-004.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openafs.org/pages/security/OPENAFS-SA-2014-001.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dkms-libafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openafs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openafs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openafs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openafs-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dkms-libafs-1.4.15-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openafs-devel-1.4.15-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openafs1-1.4.15-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"openafs-1.4.15-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"openafs-client-1.4.15-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"openafs-doc-1.4.15-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"openafs-server-1.4.15-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
