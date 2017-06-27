#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81651);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id(
    "CVE-2014-3505",
    "CVE-2014-3506",
    "CVE-2014-3507",
    "CVE-2014-3508",
    "CVE-2014-3509",
    "CVE-2014-3510",
    "CVE-2014-3511",
    "CVE-2014-3512",
    "CVE-2014-3513",
    "CVE-2014-3566",
    "CVE-2014-3567",
    "CVE-2014-3568",
    "CVE-2014-5139"
  );
  script_bugtraq_id(
    69075,
    69076,
    69077,
    69078,
    69079,
    69081,
    69082,
    69083,
    69084,
    70574,
    70584,
    70585,
    70586
  );
  script_osvdb_id(
    109891,
    109892,
    109893,
    109894,
    109895,
    109896,
    109897,
    109898,
    109902,
    113251,
    113373,
    113374,
    113377
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"Apache Tomcat 8.0.x < 8.0.15 Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Checks the Apache Tomcat Version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
server listening on the remote host is 8.0.x prior to 8.0.15. It is,
therefore, affected by the following vulnerabilities :

  - A memory double-free error exists in 'd1_both.c' related
    to handling DTLS packets that allows denial of service
    attacks. (CVE-2014-3505)

  - An unspecified error exists in 'd1_both.c' related to
    handling DTLS handshake messages that allows denial of
    service attacks due to large amounts of memory being
    consumed. (CVE-2014-3506)

  - A memory leak error exists in 'd1_both.c' related to
    handling specially crafted DTLS packets that allows
    denial of service attacks. (CVE-2014-3507)

  - An error exists in the 'OBJ_obj2txt' function when
    various 'X509_name_*' pretty printing functions are
    used, which leak process stack data, resulting in an
    information disclosure. (CVE-2014-3508)

  - An error exists related to 'ec point format extension'
    handling and multithreaded clients that allows freed
    memory to be overwritten during a resumed session.
    (CVE-2014-3509)

  - A NULL pointer dereference error exists related to
    handling anonymous ECDH cipher suites and crafted
    handshake messages that allows denial of service attacks
    against clients. (CVE-2014-3510)

  - An error exists related to handling fragmented
    'ClientHello' messages that allows a man-in-the-middle
    attacker to force usage of TLS 1.0 regardless of higher
    protocol levels being supported by both the server and
    the client. (CVE-2014-3511)

  - Buffer overflow errors exist in 'srp_lib.c' related to
    handling Secure Remote Password protocol (SRP)
    parameters, which can allow a denial of service or have
    other unspecified impact. (CVE-2014-3512)

  - A memory leak issue exists in 'd1_srtp.c' related to
    the DTLS SRTP extension handling and specially crafted
    handshake messages that can allow denial of service
    attacks. (CVE-2014-3513)

  - An error exists related to the way SSL 3.0 handles
    padding bytes when decrypting messages encrypted using
    block ciphers in cipher block chaining (CBC) mode.
    Man-in-the-middle attackers can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections. This
    is also known as the 'POODLE' issue. (CVE-2014-3566)

  - A memory leak issue exists in 't1_lib.c' related to
    session ticket handling that can allow denial of service
    attacks. (CVE-2014-3567)

  - An error exists related to the build configuration
    process and the 'no-ssl3' build option that allows
    servers and clients to process insecure SSL 3.0
    handshake messages. (CVE-2014-3568)

  - A NULL pointer dereference error exists in 't1_lib.c',
    related to handling Secure Remote Password protocol
    (SRP) ServerHello messages, which allows a malicious
    server to crash a client, resulting in a denial of
    service. (CVE-2014-5139)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/tomcat-8.0-doc/changelog.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:"Update to Apache Tomcat version 8.0.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("tomcat_version.inc");

tc_paranoia = FALSE;

# Only fire on Windows if low paranoia
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os) audit(AUDIT_OS_NOT, "Microsoft Windows");
  tc_paranoia = TRUE;
}

tomcat_check_version(fixed:"8.0.15", min:"8.0.0", severity:SECURITY_HOLE, granularity_regex:"^8(\.0)?$", paranoid:tc_paranoia);
