#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:213. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24598);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2002-1363",
    "CVE-2004-0421",
    "CVE-2004-0597",
    "CVE-2004-0598",
    "CVE-2004-0599",
    "CVE-2006-3334"
  );
  script_bugtraq_id(
    10244,
    18698,
    21078
  );
  script_osvdb_id(
    5726,
    7191,
    8312,
    8314,
    8315,
    8316,
    8326,
    28160,
    73493
  );
  script_xref(name:"MDKSA", value:"2006:213");

  script_name(english:"Mandrake Linux Security Advisory : chromium (MDKSA-2006:213)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium is an OpenGL-based shoot them up game with fine graphics. It
is built with a private copy of libpng, and as such could be
susceptible to some of the same vulnerabilities :

Buffer overflow in the png_decompress_chunk function in pngrutil.c in
libpng before 1.2.12 allows context-dependent attackers to cause a
denial of service and possibly execute arbitrary code via unspecified
vectors related to 'chunk error processing,' possibly involving the
'chunk_name'. (CVE-2006-3334)

It is questionable whether this issue is actually exploitable, but the
patch to correct the issue has been included in versions < 1.2.12.

In addition, an patch to address several old vulnerabilities has been
applied to this build. (CVE-2002-1363, CVE-2004-0421, CVE-2004-0597,
CVE-2004-0598, CVE-2004-0599)

Packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium and / or chromium-setup packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:chromium-setup");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"chromium-0.9.12-25.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"chromium-setup-0.9.12-25.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
