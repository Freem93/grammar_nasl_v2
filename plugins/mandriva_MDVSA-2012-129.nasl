#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:129. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61978);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/01 00:27:16 $");

  script_cve_id("CVE-2006-1168", "CVE-2011-2716");
  script_xref(name:"MDVSA", value:"2012:129-1");

  script_name(english:"Mandriva Linux Security Advisory : busybox (MDVSA-2012:129-1)");
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
"Multiple vulnerabilities was found and corrected in busybox :

The decompress function in ncompress allows remote attackers to cause
a denial of service (crash), and possibly execute arbitrary code, via
crafted data that leads to a buffer underflow (CVE-2006-1168).

A missing DHCP option checking / sanitization flaw was reported for
multiple DHCP clients. This flaw may allow DHCP server to trick DHCP
clients to set e.g. system hostname to a specially crafted value
containing shell special characters. Various scripts assume that
hostname is trusted, which may lead to code execution when hostname is
specially crafted (CVE-2011-2716).

Additionally for Mandriva Enterprise Server 5 various problems in the
ka-deploy and uClibc packages was discovered and fixed with this
advisory.

The updated packages have been patched to correct these issues.

Update :

The wrong set of packages was sent out with the MDVSA-2012:129
advisory that lacked the fix for CVE-2006-1168. This advisory provides
the correct packages."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected busybox and / or busybox-static packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:busybox-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", reference:"busybox-1.18.4-3.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"busybox-static-1.18.4-3.2-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
