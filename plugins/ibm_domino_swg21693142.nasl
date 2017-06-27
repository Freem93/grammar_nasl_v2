#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90512);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/15 17:43:19 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"IBM Domino SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)");
  script_summary(english:"Checks the version of IBM Domino.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Domino (formerly Lotus Domino) installed on the
remote host is affected by a man-in-the-middle (MitM) information
disclosure vulnerability, known as POODLE, due to the way SSL 3.0
handles padding bytes when decrypting messages encrypted using block
ciphers in cipher block chaining (CBC) mode. A MitM attacker can
decrypt a selected byte of a cipher text in as few as 256 tries if
they are able to force a victim application to repeatedly send the
same data over newly created SSL 3.0 connections.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21693142");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade IBM Domino according to the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_domino_installed.nasl");
  script_require_keys("installed_sw/IBM Domino");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'IBM Domino';
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install['path'];

if (!empty_or_null(install['version']))
  domino_ver = install['version'];
else
  audit(AUDIT_UNKNOWN_APP_VER, appname);

if (!empty_or_null(install['Java Version']))
  java_ver = install['Java Version'];
else
  audit(AUDIT_VER_FAIL, "jvm.dll");

vuln = FALSE ;
# Fixed versions
if(domino_ver =~ "^8\.5\.3"){
  domino_fix_raw = "8.5.36.14345";
  domino_fix  = '8.5.3 FP6 IF6';
  java_fix    = '2.4.2.24084';
}
if(domino_ver =~ "^9\.0\.0"){
  domino_fix_raw = "9.0.0.14349";
  domino_fix  = '9.0 IF7';
  java_fix    = '2.4.1.60531';
}
if(domino_ver =~ "^9\.0\.1"){
  domino_fix_raw = "9.0.10.13287";
  domino_fix  = '9.0.1 FP2 IF3';
  java_fix    = '2.4.2.65501';
}

if (ver_compare(ver:domino_ver, fix:domino_fix_raw, strict:FALSE) < 0 ||
    ver_compare(ver:java_ver, fix:java_fix, strict:FALSE) < 0){
    vuln = TRUE;
}else{
    audit(AUDIT_INST_VER_NOT_VULN, "IBM Domino ", domino_ver);
}


if(vuln){
  report =
      'The version of IBM Domino is vulnerable to TLS Padding attacks:' + 
      '\n  Path                     : ' + path +
      '\n  Domino installed version : ' + domino_ver +
      '\n  Domino installed java    : ' + java_ver +
      '\n  Domino fixed version     : ' + domino_fix +
      '\n  Java fixed version       : ' + java_fix +
      '\n' ;
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "IBM Domino ", domino_ver, path);
