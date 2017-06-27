#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78601);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id(
    "CVE-2013-3919",
    "CVE-2013-4164",
    "CVE-2013-4854",
    "CVE-2013-6393",
    "CVE-2014-0060",
    "CVE-2014-0061",
    "CVE-2014-0062",
    "CVE-2014-0063",
    "CVE-2014-0064",
    "CVE-2014-0065",
    "CVE-2014-0066",
    "CVE-2014-0591",
    "CVE-2014-3566",
    "CVE-2014-4406",
    "CVE-2014-4424",
    "CVE-2014-4446",
    "CVE-2014-4447"
  );
  script_bugtraq_id(
    60338,
    61479,
    63873,
    64801,
    65258,
    65719,
    65723,
    65724,
    65725,
    65727,
    65728,
    65731,
    69918,
    69935,
    70574
  );
  script_osvdb_id(
    93913,
    95707,
    100113,
    101973,
    102716,
    103544,
    103545,
    103546,
    103547,
    103548,
    103549,
    103551,
    111658,
    111659,
    113251,
    113426,
    113427
  );
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-10-16-3");

  script_name(english:"Mac OS X : OS X Server < 4.0 Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Checks the OS X Server version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing a security update for OS X Server.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of OS X Server installed that
is prior to version 4.0.  It is, therefore, affected by the following
vulnerabilities :

  - There are multiple vulnerabilities within the included
    BIND, the most serious of which can lead to a denial of
    service. (CVE-2013-3919, CVE-2013-4854, CVE-2014-0591)

  - There are multiple vulnerabilities within the included
    LibYAML for the Profile Manager and ServerRuby, the most
    serious of which can lead to arbitrary code execution.
    (CVE-2013-4164, CVE-2013-6393)

  - There are multiple vulnerabilities within the included
    PostgreSQL, the most serious of which can lead to
    arbitrary code execution. (CVE-2014-0060, CVE-2014-0061,
    CVE-2014-0062, CVE-2014-0063, CVE-2014-0064,
    CVE-2014-0065, CVE-2014-0066)

  - An error exists related to the way SSL 3.0 handles
    padding bytes when decrypting messages encrypted using
    block ciphers in cipher block chaining (CBC) mode. A
    man-in-the-middle attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections. This
    is also known as the 'POODLE' issue. (CVE-2014-3566)

  - A cross-site scripting flaw exists in the Xcode Server
    due to not properly validating input before returning it
    to the user. This can allow a remote attacker, using a
    specially crafted request, to execute code within the
    browser / server trust relationship. (CVE-2014-4406)

  - A SQL injection flaw exists in the Wiki Server due to
    not properly sanitizing user input before using it in
    SQL queries. This can allow a remote attacker, using a
    specially crafted request, to inject or manipulate SQL
    queries, thus allowing the manipulation or disclosure
    of arbitrary data. (CVE-2014-4424)

  - A restriction bypass flaw exists in the Mail Server due
    to SCAL changes being cached and not enforced until the
    service had restarted. This can allow an authenticated
    remote attacker to bypass those restrictions.
    (CVE-2014-4446)

  - A password disclosure flaw exists in the Profile Manager
    due to passwords being potentially saved to a file when
    editing or setting up a profile. This can allow a local
    attacker to gain access to password information.
    (CVE-2014-4447)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6536");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533722/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X Server version 4.0 or later.

Note that OS X Server 4.0 is available only for OS X 10.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "4.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
