#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3202. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82000);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/01 15:11:52 $");

  script_cve_id("CVE-2015-2318", "CVE-2015-2319", "CVE-2015-2320");
  script_bugtraq_id(73250, 73253, 73256);
  script_osvdb_id(56387, 119306, 119326);
  script_xref(name:"DSA", value:"3202");

  script_name(english:"Debian DSA-3202-1 : mono - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Researchers at INRIA and Xamarin discovered several vulnerabilities in
mono, a platform for running and developing applications based on the
ECMA/ISO Standards. Mono's TLS stack contained several problems that
hampered its capabilities: those issues could lead to client
impersonation (via SKIP-TLS), SSLv2 fallback, and encryption weakening
(via FREAK)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=780751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mono"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3202"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mono packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.10.8.1-8+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mono");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"libmono-2.0-1", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-2.0-1-dbg", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-2.0-dev", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-accessibility2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-accessibility4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-c5-1.1-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-cairo2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-cairo4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-cecil-private-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-cil-dev", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-codecontracts4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-compilerservices-symbolwriter4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-corlib2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-corlib4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-cscompmgd8.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-csharp4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-custommarshalers4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-data-tds2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-data-tds4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-db2-1.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-debugger-soft2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-debugger-soft4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-http4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n-cjk4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n-mideast4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n-other4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n-rare4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n-west2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n-west4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n4.0-all", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-i18n4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-ldap2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-ldap4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-management2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-management4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-messaging-rabbitmq2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-messaging-rabbitmq4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-messaging2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-messaging4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft-build-engine4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft-build-framework4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft-build-tasks-v4.0-4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft-build-utilities-v4.0-4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft-build2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft-csharp4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft-visualc10.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft-web-infrastructure1.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-microsoft8.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-npgsql2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-npgsql4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-opensystem-c4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-oracle2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-oracle4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-peapi2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-peapi4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-posix2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-posix4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-profiler", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-rabbitmq2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-rabbitmq4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-relaxng2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-relaxng4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-security2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-security4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-sharpzip2.6-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-sharpzip2.84-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-sharpzip4.84-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-simd2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-simd4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-sqlite2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-sqlite4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-componentmodel-composition4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-componentmodel-dataannotations4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-configuration-install4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-configuration4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-core4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-data-datasetextensions4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-data-linq2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-data-linq4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-data-services-client4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-data-services4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-data2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-data4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-design4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-drawing-design4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-drawing4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-dynamic4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-enterpriseservices4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-identitymodel-selectors4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-identitymodel4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-ldap2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-ldap4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-management4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-messaging2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-messaging4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-net4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-numerics4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-runtime-caching4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-runtime-durableinstancing4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-runtime-serialization-formatters-soap4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-runtime-serialization4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-runtime2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-runtime4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-security4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-servicemodel-discovery4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-servicemodel-routing4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-servicemodel-web4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-servicemodel4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-serviceprocess4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-transactions4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-abstractions4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-applicationservices4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-dynamicdata4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-extensions-design4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-extensions4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-mvc1.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-mvc2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-routing4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web-services4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-web4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-windows-forms-datavisualization4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-windows-forms4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-xaml4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-xml-linq4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system-xml4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-system4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-tasklets2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-tasklets4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-wcf3.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-web4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-webbrowser2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-webbrowser4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-webmatrix-data4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-windowsbase3.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-windowsbase4.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono-winforms2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmono2.0-cil", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-2.0-gac", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-2.0-service", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-4.0-gac", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-4.0-service", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-complete", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-csharp-shell", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-dbg", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-devel", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-dmcs", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-gac", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-gmcs", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-jay", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-mcs", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-runtime", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-runtime-dbg", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-runtime-sgen", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-utils", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mono-xbuild", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"monodoc-base", reference:"2.10.8.1-8+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"monodoc-manual", reference:"2.10.8.1-8+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
