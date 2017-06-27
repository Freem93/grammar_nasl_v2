#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:170. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56809);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2011-3377",
    "CVE-2011-3389",
    "CVE-2011-3521",
    "CVE-2011-3544",
    "CVE-2011-3547",
    "CVE-2011-3548",
    "CVE-2011-3551",
    "CVE-2011-3552",
    "CVE-2011-3553",
    "CVE-2011-3554",
    "CVE-2011-3556",
    "CVE-2011-3557",
    "CVE-2011-3558",
    "CVE-2011-3560"
  );
  script_bugtraq_id(
    49778,
    50211,
    50215,
    50216,
    50218,
    50224,
    50231,
    50234,
    50236,
    50242,
    50243,
    50246,
    50248,
    50610
  );
  script_osvdb_id(
    74829,
    76495,
    76496,
    76497,
    76498,
    76500,
    76502,
    76505,
    76506,
    76507,
    76510,
    76511,
    76512,
    76940
  );
  script_xref(name:"MDVSA", value:"2011:170");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2011:170)");
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
"Security issues were identified and fixed in openjdk (icedtea6) and
icedtea-web :

IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
applications and untrusted Java applets to affect confidentiality via
unknown vectors related to Networking (CVE-2011-3547).

IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
applications and untrusted Java applets to affect confidentiality,
integrity, and availability, related to AWT (CVE-2011-3548).

IcedTea6 prior to 1.10.4 allows remote attackers to affect
confidentiality, integrity, and availability via unknown vectors
related to 2D (CVE-2011-3551).

IcedTea6 prior to 1.10.4 allows remote attackers to affect integrity
via unknown vectors related to Networking (CVE-2011-3552).

IcedTea6 prior to 1.10.4 allows remote authenticated users to affect
confidentiality, related to JAXWS (CVE-2011-3553).

IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
applications and untrusted Java applets to affect confidentiality,
integrity, and availability via unknown vectors related to Scripting
(CVE-2011-3544).

IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
applications and untrusted Java applets to affect confidentiality,
integrity, and availability via unknown vectors related to
Deserialization (CVE-2011-3521).

IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
applications and untrusted Java applets to affect confidentiality,
integrity, and availability via unknown vectors (CVE-2011-3554).

A flaw was found in the way the SSL 3 and TLS 1.0 protocols used block
ciphers in cipher-block chaining (CBC) mode. An attacker able to
perform a chosen plain text attack against a connection mixing trusted
and untrusted data could use this flaw to recover portions of the
trusted data sent over the connection (CVE-2011-3389).

Note: This update mitigates the CVE-2011-3389 issue by splitting the
first application data record byte to a separate SSL/TLS protocol
record. This mitigation may cause compatibility issues with some
SSL/TLS implementations and can be disabled using the
jsse.enableCBCProtection boolean property. This can be done on the
command line by appending the flag -Djsse.enableCBCProtection=false to
the java command.

IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
applications and untrusted Java applets to affect confidentiality via
unknown vectors related to HotSpot (CVE-2011-3558).

IcedTea6 prior to 1.10.4 allows remote attackers to affect
confidentiality, integrity, and availability, related to RMI
(CVE-2011-3556).

IcedTea6 prior to 1.10.4 allows remote attackers to affect
confidentiality, integrity, and availability, related to RMI
(CVE-2011-3557).

IcedTea6 prior to 1.10.4 allows remote untrusted Java Web Start
applications and untrusted Java applets to affect confidentiality and
integrity, related to JSSE (CVE-2011-3560).

Deepak Bhole discovered a flaw in the Same Origin Policy (SOP)
implementation in the IcedTea project Web browser plugin. A malicious
applet could use this flaw to bypass SOP protection and open
connections to any sub-domain of the second-level domain of the
applet's origin, as well as any sub-domain of the domain that is the
suffix of the origin second-level domain. For example, IcedTea-Web
plugin allowed applet from some.host.example.com to connect to
other.host.example.com, www.example.com, and example.com, as well as
www.ample.com or ample.com. (CVE-2011-3377)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"icedtea-web-1.0.6-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-1.6.0.0-24.b22.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-demo-1.6.0.0-24.b22.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-devel-1.6.0.0-24.b22.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-24.b22.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"java-1.6.0-openjdk-src-1.6.0.0-24.b22.1mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", reference:"icedtea-web-1.0.6-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-1.6.0.0-24.b22.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-demo-1.6.0.0-24.b22.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-devel-1.6.0.0-24.b22.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-24.b22.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"java-1.6.0-openjdk-src-1.6.0.0-24.b22.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
