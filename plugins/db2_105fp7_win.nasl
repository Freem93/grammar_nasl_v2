#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87765);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 14:38:50 $");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-1788",
    "CVE-2015-1947",
    "CVE-2015-2808",
    "CVE-2015-4000"
  );
  script_bugtraq_id(
    71936,
    73684,
    74733,
    75158,
    79693
  );
  script_osvdb_id(
    116794,
    117855,
    122331,
    123172,
    132442
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"IBM DB2 10.5 < Fix Pack 7 Multiple Vulnerabilities (Bar Mitzvah) (FREAK) (Logjam)");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 10.5 running on
the remote host is prior to Fix Pack 7. It is, therefore, affected by
the following vulnerabilities :

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - A privilege escalation vulnerability exists due to an
    untrusted search path flaw. A local attacker can exploit
    this, via a specially crafted library that is loaded by
    a setuid or setgid process, to gain elevated privileges
    on the system. (CVE-2015-1947)

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

Note that several of these vulnerabilities are due to the bundled
GSKit component and the embedded FCM 4.1 libraries.");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21647054#7");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT07394");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT08753");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT09900");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT09964");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IT09969");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 10.5 Fix Pack 7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_ports("SMB/db2/Installed", "SMB/db2_connect/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check each installation.
db2_installed = get_kb_item("SMB/db2/Installed");
if (db2_installed)
  db2_installs = get_kb_list("SMB/db2/*");

db2connect_installed = get_kb_item("SMB/db2_connect/Installed");
if (db2_installed)
  db2connect_installs = get_kb_list("SMB/db2_connect/*");

if (!db2_installed && !db2connect_installed)
  audit(AUDIT_NOT_INST, "DB2 and/or DB2 Connect");

info = "";
fix_version = '10.5.700.375';
not_affected = make_list();

# Check DB2 first
foreach install(sort(keys(db2_installs)))
{
  if ("/Installed" >< install) continue;

  version = db2_installs[install];

  prod = install - "SMB/db2/";
  prod = prod - (strstr(prod, "/"));

  path = install - "SMB/db2/";
  path = path - (prod + "/");

  if (version =~ "^10\.5\." && ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_version +
      '\n';
  }
  else
    not_affected = make_list(not_affected, prod + ' version ' + version + ' at ' + path);
}

# Check DB2 Connect second
foreach install(sort(keys(db2connect_installs)))
{
  if ("/Installed" >< install) continue;

  version = db2connect_installs[install];

  prod = install - "SMB/db2_connect/";
  prod = prod - (strstr(prod, "/"));

  path = install - "SMB/db2_connect/";
  path = path - (prod + "/");

  if (version =~ "^10\.5\." && ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_version +
      '\n';
  }
  else
    not_affected = make_list(not_affected, prod + ' version ' + version + ' at ' + path);
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

# Report if vulnerable installs were found.
if (info)
{

  if (report_verbosity > 0)
    security_warning(port:port, extra:info);
  else security_warning(port);
  exit(0);
}
else
{
  if (max_index(not_affected) > 1)
    exit(0, join(not_affected, sep:", ") + " are installed and, therefore, not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, not_affected[0]);
}
