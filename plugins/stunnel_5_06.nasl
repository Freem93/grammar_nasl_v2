#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78584);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/07/29 16:23:47 $");

  script_cve_id(
    "CVE-2014-3513",
    "CVE-2014-3566",
    "CVE-2014-3567",
    "CVE-2014-3568"
  );
  script_bugtraq_id(70574, 70584, 70585, 70586);
  script_osvdb_id(113251, 113373, 113374, 113377);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"stunnel < 5.06 OpenSSL Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Checks the version of stunnel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of stunnel installed on the remote host is prior to
version 5.06. It is, therefore, affected by the following
vulnerabilities in the bundled OpenSSL library :

  - An error exists related to DTLS SRTP extension handling
    and specially crafted handshake messages that can allow
    denial of service attacks via memory leaks.
    (CVE-2014-3513)

  - An error exists related to the way SSL 3.0 handles
    padding bytes when decrypting messages encrypted using
    block ciphers in cipher block chaining (CBC) mode. A
    man-in-the-middle attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections. This
    is also known as the 'POODLE' issue. (CVE-2014-3566)

  - An error exists related to session ticket handling that
    can allow denial of service attacks via memory leaks.
    (CVE-2014-3567)

  - An error exists related to the build configuration
    process and the 'no-ssl3' build option that allows
    servers and clients to process insecure SSL 3.0
    handshake messages. (CVE-2014-3568)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://stunnel.org/?page=sdf_ChangeLog");
  # https://www.stunnel.org/pipermail/stunnel-announce/2014-October/000084.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d459ce27");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.1-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:"Upgrade to stunnel version 5.06 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("stunnel_installed.nasl");
  script_require_keys("installed_sw/stunnel");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'stunnel';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

# Affected < 5.06
if (
  version =~ "^[0-4]\." ||
  version =~ "^5\.0[0-5]($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.06' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
