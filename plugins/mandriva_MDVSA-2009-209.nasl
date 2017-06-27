#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:209. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40694);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id(
    "CVE-2009-0217",
    "CVE-2009-1896",
    "CVE-2009-2475",
    "CVE-2009-2476",
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2673",
    "CVE-2009-2674",
    "CVE-2009-2675",
    "CVE-2009-2689",
    "CVE-2009-2690"
  );
  script_bugtraq_id(
    35671,
    35922,
    35939,
    35942,
    35943,
    35944,
    35958
  );
  script_osvdb_id(
    56243,
    56783,
    56785,
    56786,
    56787,
    56788,
    56965,
    56966,
    56967,
    56968,
    56972,
    56984
  );
  script_xref(name:"MDVSA", value:"2009:209");

  script_name(english:"Mandriva Linux Security Advisory : java-1.6.0-openjdk (MDVSA-2009:209)");
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
"Multiple Java OpenJDK security vulnerabilities has been identified and
fixed :

The design of the W3C XML Signature Syntax and Processing (XMLDsig)
recommendation specifies an HMAC truncation length (HMACOutputLength)
but does not require a minimum for its length, which allows attackers
to spoof HMAC-based signatures and bypass authentication by specifying
a truncation length with a small number of bits (CVE-2009-0217).

The Java Web Start framework does not properly check all application
jar files trust and this allows context-dependent attackers to execute
arbitrary code via a crafted application, related to NetX
(CVE-2009-1896).

Some variables and data structures without the final keyword
definition allows context-depend attackers to obtain sensitive
information. The target variables and data structures are stated as
follow: (1) LayoutQueue, (2) Cursor.predefined, (3)
AccessibleResourceBundle.getContents, (4)
ImageReaderSpi.STANDARD_INPUT_TYPE, (5)
ImageWriterSpi.STANDARD_OUTPUT_TYPE, (6) the imageio plugins, (7)
DnsContext.debug, (8) RmfFileReader/StandardMidiFileWriter.types, (9)
AbstractSaslImpl.logger, (10)
Synth.Region.uiToRegionMap/lowerCaseNameMap, (11) the Introspector
class and a cache of BeanInfo, and (12) JAX-WS (CVE-2009-2475).

The Java Management Extensions (JMX) implementation does not properly
enforce OpenType checks, which allows context-dependent attackers to
bypass intended access restrictions by leveraging finalizer
resurrection to obtain a reference to a privileged object
(CVE-2009-2476).

A flaw in the Xerces2 as used in OpenJDK allows remote attackers to
cause denial of service via a malformed XML input (CVE-2009-2625).

The audio system does not prevent access to java.lang.System
properties either by untrusted applets and Java Web Start
applications, which allows context-dependent attackers to obtain
sensitive information by reading these properties (CVE-2009-2670).

A flaw in the SOCKS proxy implementation allows remote attackers to
discover the user name of the account that invoked either an untrusted
applet or Java Web Start application via unspecified vectors
(CVE-2009-2671).

A flaw in the proxy mechanism implementation allows remote attackers
to bypass intended access restrictions and connect to arbitrary sites
via unspecified vectors, related to a declaration that lacks the final
keyword (CVE-2009-2673).

An integer overflow in the JPEG images parsing allows
context-dependent attackers to gain privileges via an untrusted Java
Web Start application that grants permissions to itself
(CVE-2009-2674).

An integer overflow in the unpack200 utility decompression allows
context-dependent attackers to gain privileges via vectors involving
either an untrusted applet or Java Web Start application that grants
permissions to itself (CVE-2009-2675).

A flaw in the JDK13Services.getProviders grants full privileges to
instances of unspecified object types, which allows context-dependent
attackers to bypass intended access restrictions either via an
untrusted applet or application (CVE-2009-2689).

A flaw in the OpenJDK's encoder, grants read access to private
variables with unspecified names, which allows context-dependent
attackers to obtain sensitive information either via an untrusted
applet or application (CVE-2009-2690)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-1.6.0.0-0.20.b16.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.20.b16.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.20.b16.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.20.b16.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-0.20.b16.0.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"java-1.6.0-openjdk-src-1.6.0.0-0.20.b16.0.3mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-1.6.0.0-0.20.b16.0.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.20.b16.0.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.20.b16.0.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.20.b16.0.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-plugin-1.6.0.0-0.20.b16.0.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"java-1.6.0-openjdk-src-1.6.0.0-0.20.b16.0.3mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
