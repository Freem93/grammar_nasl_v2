#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99593);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:26:21 $");

  script_cve_id(
    "CVE-2016-3092",
    "CVE-2016-7055",
    "CVE-2017-3306",
    "CVE-2017-3307",
    "CVE-2017-3731",
    "CVE-2017-3732",
    "CVE-2017-5638"
  );
  script_bugtraq_id(
    91453,
    94242,
    95813,
    96729,
    97724,
    97844
  );
  script_osvdb_id(
    140354,
    147021,
    151018,
    151020,
    153025,
    155873,
    155901
  );
  script_xref(name:"CERT", value:"834067");
  script_xref(name:"IAVA", value:"2017-A-0118");
  script_xref(name:"EDB-ID", value:"41570");
  script_xref(name:"EDB-ID", value:"41614");

  script_name(english:"MySQL Enterprise Monitor 3.1.x < 3.1.7.8023 / 3.2.x < 3.2.7.1204 / 3.3.x < 3.3.3.1199 Multiple Vulnerabilities (April 2017 CPU)");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
application running on the remote host is 3.1.x prior to 3.1.7.8023,
3.2.x prior to 3.2.7.1204, or 3.3.x < 3.3.3.1199. It is, therefore,
affected by multiple vulnerabilities :

  - A denial of service vulnerability exists in the Apache
    Commons component in the FileUpload functionality due to
    improper handling of file upload requests. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted content-type header, to cause a denial
    of service condition. Note that this vulnerability does
    not affect MySQL Enterprise Monitor versions 3.3.x.
    (CVE-2016-3092)

  - A carry propagation error exists in the OpenSSL
    component in the Broadwell-specific Montgomery
    multiplication procedure when handling input lengths
    divisible by but longer than 256 bits. This can result
    in transient authentication and key negotiation failures
    or reproducible erroneous outcomes of public-key
    operations with specially crafted input. A
    man-in-the-middle attacker can possibly exploit this
    issue to compromise ECDH key negotiations that utilize
    Brainpool P-512 curves. (CVE-2016-7055)

  - An unspecified flaw exists in the Web Services
    subcomponent that allows an unauthenticated, remote
    attacker to modify or delete arbitrary data accessible
    to the server. (CVE-2017-3506)

  - An unspecified flaw exists in the Server subcomponent
    that allows an authenticated, remote attacker to update,
    insert, or delete or arbitrary data. (CVE-2017-3507)

  - An out-of-bounds read error exists in the OpenSSL
    component when handling packets using the
    CHACHA20/POLY1305 or RC4-MD5 ciphers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted truncated packets, to cause a denial
    of service condition. (CVE-2017-3731)

  - A carry propagating error exists in the OpenSSL
    component in the x86_64 Montgomery squaring
    implementation that may cause the BN_mod_exp() function
    to produce incorrect results. An unauthenticated, remote
    attacker with sufficient resources can exploit this to
    obtain sensitive information regarding private keys.
    (CVE-2017-3732)

  - A remote code execution vulnerability exists in the
    Apache Struts component in the Jakarta Multipart parser
    due to improper handling of the Content-Type,
    Content-Disposition, and Content-Length headers.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted header value in the HTTP
    request, to execute arbitrary code. (CVE-2017-5638)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54d9438d");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e1362c");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2244179.1");
  script_set_attribute(attribute:"see_also", value:"http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html");
  # https://threatpost.com/apache-struts-2-exploits-installing-cerber-ransomware/124844/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77e9c654");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 3.1.7.8023 / 3.2.7.1204 /
3.3.3.1199 or later as referenced in the April 2017 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Jakarta Multipart Parser OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor", "Settings/ParanoidReport");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app  = "MySQL Enterprise Monitor";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:18443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
install_url = build_url(port:port, qs:"/");

fixes = {"^3.3": "3.3.3.1199",
         "^3.2": "3.2.7.1204",
         "^3.1": "3.1.7.8023"};

vuln = FALSE;
fix = '';
foreach (prefix in keys(fixes))
{
  if (version =~ prefix && ver_compare(ver:version,
                                       fix:fixes[prefix],
                                       strict:FALSE) < 0)
  { 
    vuln = TRUE;
    fix = fixes[prefix];
    break;
  }
}

if (vuln)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
