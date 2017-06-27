#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80890);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2014-6593",
    "CVE-2015-0383",
    "CVE-2015-0410"
  );
  script_bugtraq_id(
    70574,
    72155,
    72165,
    72169
  );
  script_osvdb_id(
    113251,
    117236,
    117238,
    117241
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"Oracle JRockit R27.8.4 / R28.3.4 Multiple Vulnerabilities (January 2015 CPU) (POODLE)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle JRockit that is affected by
multiple vulnerabilities in the following components :

  - Hotspot
  - JSSE
  - Security

Note that CVE-2014-3566 is an error related to the way SSL 3.0 handles
padding bytes when decrypting messages encrypted using block ciphers
in cipher block chaining (CBC) mode. A man-in-the-middle attacker can
decrypt a selected byte of a cipher text in as few as 256 tries if
they are able to force a victim application to repeatedly send the
same data over newly created SSL 3.0 connections. This is also known
as the 'POODLE' issue.");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version R27.8.5 / R28.3.5 or later as referenced in the
January 2015 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Oracle JRockit";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

fix     = NULL;

if (ver =~ "^27\.8\.4($|[^0-9])")
  fix = "27.8.5";
else if (ver =~ "^28\.3\.4($|[^0-9])")
  fix = "28.3.5";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

# The DLL we're looking at is a level deeper in the JDK, since it
# keeps a subset of the JRE in a subdirectory.
if (type == "JDK")  path += "\jre";

path += "\bin\jrockit\jvm.dll";

report =
  '\n  Type              : ' + type +
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
