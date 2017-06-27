#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84960);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id(
    "CVE-2014-3600",
    "CVE-2014-3612",
    "CVE-2014-8110",
    "CVE-2014-8176",
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-3165",
    "CVE-2015-3166",
    "CVE-2015-3167",
    "CVE-2015-4000"
  );
  script_bugtraq_id(
    72510,
    72511,
    72513,
    74733,
    74787,
    74789,
    74790,
    75154,
    75156,
    75157,
    75158,
    75159,
    75161
  );
  script_osvdb_id(
    63367,
    118027,
    118028,
    118030,
    118040,
    118041,
    122331,
    122456,
    122457,
    122458,
    122875,
    123172,
    123173,
    123174,
    123175,
    123176
  );

  script_name(english:"Puppet Enterprise 3.x < 3.8.1 Multiple Vulnerabilities (Logjam)");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
application running on the remote host is 3.x prior to 3.8.1. It is,
therefore, affected by the following vulnerabilities :

  - An XML external entity injection (XXE) flaw exists in
    the Apache ActiveMQ component due to a faulty
    configuration that allows an XML parser to accept XML
    external entities from untrusted sources. A remote
    attacker, by sending crafted XML data, can exploit this
    to disclose arbitrary files. (CVE-2014-3600)

  - An authentication bypass vulnerability exists in the
    Apache ActiveMQ component due to a flaw in the
    LDAPLoginModule implementation. A remote attacker can
    exploit this to bypass authentication mechanisms.
    (CVE-2014-3612)

  - Multiple cross-site scripting vulnerabilities exist in
    the administrative console of Apache ActiveMQ that allow
    a remote attacker to inject arbitrary HTML or web
    scripts. (CVE-2014-8110)

  - An invalid free memory error exists due to improper
    validation of user-supplied input when a DTLS peer
    receives application data between ChangeCipherSpec and
    Finished messages. A remote attacker can exploit this to
    corrupt memory, resulting in a denial of service or
    the execution of arbitrary code. (CVE-2014-8176)

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the ASN1_TIME
    string by the X509_cmp_time() function. A remote
    attacker can exploit this, via a malformed certificate
    and CRLs of various sizes, to cause a segmentation
    fault, resulting in a denial of service condition. TLS
    clients that verify CRLs are affected. TLS clients and
    servers with client authentication enabled may be
    affected if they use custom verification callbacks.
    (CVE-2015-1789)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing inner
    'EncryptedContent'. This allows a remote attacker, via
    specially crafted ASN.1-encoded PKCS#7 blobs with
    missing content, to cause a denial of service condition
    or other potential unspecified impacts. (CVE-2015-1790)

  - A double-free error exists due to a race condition that
    occurs when a NewSessionTicket is received by a
    multi-threaded client when attempting to reuse a
    previous ticket. (CVE-2015-1791)

  - A denial of service vulnerability exists in the CMS code
    due to an infinite loop that occurs when verifying a
    signedData message. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-1792)

  - A double-free memory flaw exists in PostgreSQL due to
    a timeout interrupt occurring partway in the session
    shutdown sequence. A remote attacker, by closing
    an SSL session when the authentication timeout expires,
    can exploit this flaw to cause a denial of service.
    (CVE-2015-3165)

  - An out-of-memory condition exists in the printf()
    functions in PostgreSQL due to a failure to check for
    errors. A remote attacker can exploit this to access
    sensitive information. (CVE-2015-3166)

  - A flaw exists in contrib/pgcrypto in PostgreSQL due
    to cases of decryption reporting other error message
    texts, which a remote attacker can use to recover
    keys from other systems. (CVE-2015-3167)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)");
  # https://puppetlabs.com/security/cve/activemq-february-2015-vulnerability-fix
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53e717cd");
  # https://puppetlabs.com/security/cve/postgresql-may-2015-vulnerability-fix
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74383813");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1587/");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/CVE-2015-4000");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/openssl-june-2015-vulnerability-fix");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150611.txt");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet Enterprise version 3.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("puppet_rest_detect.nasl");
  script_require_keys("puppet/rest_port");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_misc_func.inc");

app_name = "Puppet Enterprise";

port = get_kb_item_or_exit('puppet/rest_port');
ver = get_kb_item_or_exit('puppet/' + port + '/version');

if ('Enterprise' >< ver)
{
  # convert something like
  #   2.7.19 (Puppet Enterprise 2.7.0)
  # to
  #   2.7.0
  match = eregmatch(string:ver, pattern:"Enterprise ([0-9.]+)\)");
  if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_APP_VER, app_name, build_url(port:port));
  ver = match[1];
}
else audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

if (
  ver =~ "^3\.[0-7]($|[^0-9])" ||
  ver =~ "^3\.8\.0($|[^0-9])"
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : Puppet Enterprise ' + ver +
      '\n  Fixed version     : Puppet Enterprise 3.8.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port), ver);
