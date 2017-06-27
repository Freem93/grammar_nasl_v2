#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory java_feb2015_advisory.asc
#

include("compat.inc");

if (description)
{
  script_id(81491);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2014-6549",
    "CVE-2014-6585",
    "CVE-2014-6587",
    "CVE-2014-6591",
    "CVE-2014-6593",
    "CVE-2014-8891",
    "CVE-2015-0400",
    "CVE-2015-0403",
    "CVE-2015-0406",
    "CVE-2015-0407",
    "CVE-2015-0408",
    "CVE-2015-0410",
    "CVE-2015-0412"
  );
  script_bugtraq_id(
    70574,
    72136,
    72137,
    72140,
    72148,
    72154,
    72159,
    72162,
    72165,
    72168,
    72169,
    72173,
    72175
  );
  script_osvdb_id(
    113251,
    117225,
    117226,
    117227,
    117230,
    117232,
    117233,
    117235,
    117236,
    117237,
    117238,
    117239,
    117240,
    118009
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"AIX Java Advisory : java_feb2015_advisory.asc (POODLE)");
  script_summary(english:"Checks the version of the Java package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of Java SDK installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Java SDK installed on the remote host is affected by
the following vulnerabilities :

  - A man-in-the-middle (MitM) information disclosure
    vulnerability known as POODLE. The vulnerability is due
    to the way SSL 3.0 handles padding bytes when decrypting
    messages encrypted using block ciphers in cipher block
    chaining (CBC) mode. MitM attackers can decrypt a
    selected byte of a cipher text in as few as 256 tries if
    they are able to force a victim application to
    repeatedly send the same data over newly created SSL 3.0
    connections. (CVE-2014-3566)

  - Information disclosure flaws exist in the font parsing
    code in the 2D component in OpenJDK. A specially crafted
    font file can exploit boundary check flaws and allow an
    untrusted Java applet or application to disclose
    portions of the Java Virtual Machine memory.
    (CVE-2014-6585, CVE-2014-6591)

  - A NULL pointer dereference flaw exists in the
    MulticastSocket implementation in the Libraries
    component of OpenJDK. An untrusted Java applet or
    application can use this flaw to bypass certain
    Java sandbox restrictions. (CVE-2014-6587)

  - The SSL/TLS implementation in the JSSE component in
    OpenJDK fails to properly check whether the
    ChangeCipherSpec was received during a SSL/TLS
    connection handshake. An MitM attacker can use this
    flaw to force a connection to be established without
    encryption being enabled. (CVE-2014-6593)

  - An unspecified privilege escalation vulnerability exists
    in IBM Java Virtual Machine. (CVE-2014-8891)

  - An unspecified information disclosure vulnerability
    exists in the Libraries component of Oracle Java SE.
    (CVE-2015-0400)

  - An unspecified information disclosure vulnerability
    exists in the Deployment component of Oracle Java SE.
    (CVE-2015-0403)

  - Unspecified denial of service and information
    disclosure vulnerabilities exist in the Deployment
    component of Oracle Java SE. (CVE-2015-0406)

  - An information disclosure vulnerability exists in the
    Swing component in OpenJDK. An untrusted Java applet or
    application can use this flaw to bypass certain Java
    sandbox restrictions. (CVE-2015-0407)

  - Multiple improper permission check vulnerabilities exist
    in the JAX-WS, Libraries, and RMI components in OpenJDK.
    An untrusted Java applet or application can use these
    flaws to bypass Java sandbox restrictions.
    (CVE-2015-0412, CVE-2014-6549, CVE-2015-0408)

  - A denial of service vulnerability exists in the DER
    (Distinguished Encoding Rules) decoder in the Security
    component in OpenJDK when handling negative length
    values. A specially crafted, DER-encoded input can cause
    a Java application to enter an infinite loop when
    decoded. (CVE-2015-0410)");
  # http://aix.software.ibm.com/aix/efixes/security/java_feb2015_advisory.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be2ce7c9");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dka&S_PKG=aix32j5b&S_TACT=105AGX05&S_CMP=JDK&lang=en_US&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aacaab25");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dka&S_PKG=aix64j5b&S_TACT=105AGX05&S_CMP=JDK&lang=en_US&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70623e16");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dka&S_PKG=aix32j6b&S_TACT=105AGX05&S_CMP=JDK&lang=en_US&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d08dc51");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dka&S_PKG=aix64j6b&S_TACT=105AGX05&S_CMP=JDK&lang=en_US&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ca2561a");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dka&S_PKG=aix32j7b&S_TACT=105AGX05&S_CMP=JDK&lang=en_US&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a624fae8");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dka&S_PKG=aix64j7b&S_TACT=105AGX05&S_CMP=JDK&lang=en_US&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa3fc787");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dka&S_PKG=aix32j7r1&S_TACT=105AGX05&S_CMP=JDK&lang=en_US&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e42e2673");
  # https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=dka&S_PKG=aix64j7r1&S_TACT=105AGX05&S_CMP=JDK&lang=en_US&cp=UTF-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae6bb0ba");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/developerworks/java/jdk/aix/service.html#levels");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Fixes are available by version and can be downloaded from the IBM AIX
website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-5.3" && oslevel != "AIX-6.1" && oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1", oslevel);
}
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

#Java5 5.0.0.590
if (aix_check_package(release:"5.3", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.589", fixpackagever:"5.0.0.590") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.589", fixpackagever:"5.0.0.590") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.589", fixpackagever:"5.0.0.590") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.589", fixpackagever:"5.0.0.590") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.589", fixpackagever:"5.0.0.590") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java5_64.sdk", minpackagever:"5.0.0.0", maxpackagever:"5.0.0.589", fixpackagever:"5.0.0.590") > 0) flag++;


#Java6 6.0.0.470
if (aix_check_package(release:"5.3", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.469", fixpackagever:"6.0.0.470") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.469", fixpackagever:"6.0.0.470") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.469", fixpackagever:"6.0.0.470") > 0) flag++;
if (aix_check_package(release:"5.3", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.469", fixpackagever:"6.0.0.470") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.469", fixpackagever:"6.0.0.470") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java6_64.sdk", minpackagever:"6.0.0.0", maxpackagever:"6.0.0.469", fixpackagever:"6.0.0.470") > 0) flag++;

#Java7 7.0.0.195
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.194", fixpackagever:"7.0.0.195") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.194", fixpackagever:"7.0.0.195") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.194", fixpackagever:"7.0.0.195") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.0.0.0", maxpackagever:"7.0.0.194", fixpackagever:"7.0.0.195") > 0) flag++;

#Java7.1 7.1.0.75
if (aix_check_package(release:"6.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.74", fixpackagever:"7.1.0.75") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.74", fixpackagever:"7.1.0.75") > 0) flag++;
if (aix_check_package(release:"6.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.74", fixpackagever:"7.1.0.75") > 0) flag++;
if (aix_check_package(release:"7.1", package:"Java7_64.sdk", minpackagever:"7.1.0.0", maxpackagever:"7.1.0.74", fixpackagever:"7.1.0.75") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Java5 / Java6 / Java7");
}
